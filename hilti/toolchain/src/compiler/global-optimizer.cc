// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#include "hilti/compiler/global-optimizer.h"

#include <algorithm>
#include <optional>
#include <string>
#include <tuple>
#include <utility>

#include <hilti/rt/util.h>

#include <hilti/ast/builder/expression.h>
#include <hilti/ast/ctors/default.h>
#include <hilti/ast/declarations/function.h>
#include <hilti/ast/declarations/imported-module.h>
#include <hilti/ast/detail/visitor.h>
#include <hilti/ast/expressions/ctor.h>
#include <hilti/ast/node.h>
#include <hilti/ast/scope-lookup.h>
#include <hilti/ast/statements/block.h>
#include <hilti/ast/types/bool.h>
#include <hilti/ast/types/enum.h>
#include <hilti/ast/types/reference.h>
#include <hilti/ast/types/struct.h>
#include <hilti/base/logger.h>
#include <hilti/base/timing.h>
#include <hilti/base/util.h>
#include <hilti/base/visitor.h>

namespace hilti {

namespace logging::debug {
inline const DebugStream GlobalOptimizer("global-optimizer");
} // namespace logging::debug

template<typename Position>
void replaceNode(Position& p, Node replacement) {
    p.node = std::move(replacement);
}

template<typename Position>
static void removeNode(Position& p) {
    replaceNode(p, node::none);
}

// Helper function to extract innermost type, removing any wrapping in reference or container types.
Type innermostType(Type type) {
    if ( type::isReferenceType(type) )
        return innermostType(type.dereferencedType());

    if ( type::isIterable(type) )
        return innermostType(type.elementType());

    return type;
}

class OptimizerVisitor {
public:
    enum class Stage { COLLECT, PRUNE_USES, PRUNE_DECLS };
    Stage _stage = Stage::COLLECT;

    virtual ~OptimizerVisitor() = default;
    virtual void collect(Node&) {}
    virtual bool prune_uses(Node&) { return false; }
    virtual bool prune_decls(Node&) { return false; }
};

struct FunctionVisitor : OptimizerVisitor, visitor::PreOrder<bool, FunctionVisitor> {
    using ModuleID = ID;
    using StructID = ID;
    using FieldID = ID;

    struct Uses {
        bool hook = false;
        bool defined = false;
        bool referenced = false;
    };

    using Identifier = std::string;
    using Functions = std::map<Identifier, Uses>;

    Functions _data;

    template<typename T>
    static std::optional<std::pair<ModuleID, StructID>> typeID(T&& x) {
        auto id = x.typeID();
        if ( ! id )
            return {};

        return {{id->sub(-2), id->sub(-1)}};
    }

    static auto function_identifier(const declaration::Function& fn, position_t p) {
        // A current module should always be exist, but might
        // not necessarily be the declaration's module.
        const auto& current_module = p.findParent<Module>();
        assert(current_module);

        const auto& id = fn.id();
        const auto local = id.local();

        auto ns = id.namespace_();

        // If the namespace is empty, we are dealing with a global function in the current module.
        if ( ns.empty() )
            return std::make_tuple(current_module->get().id(), ID(), local);

        auto ns_ns = ns.namespace_();
        auto ns_local = ns.local();

        // If the namespace is a single component (i.e., has no namespace itself) we are either dealing
        // with a global function in another module, or a function for a struct in the current module.
        if ( ns_ns.empty() ) {
            const auto imports = current_module->get().childsOfType<declaration::ImportedModule>();
            if ( std::any_of(imports.begin(), imports.end(), [&](const auto& imported_module) {
                     if ( const auto& m = imported_module.module() )
                         return m->id() == ns_local;
                     return false;
                 }) )
                return std::make_tuple(ns_local, ID(), local);

            else
                return std::make_tuple(current_module->get().id(), ns_local, local);
        }

        // If the namespace has multiple components, we are dealing with a method definition in another module.
        return std::make_tuple(ns_ns, ns_local, local);
    }

    static std::optional<Identifier> getID(const type::struct_::Field& x, position_t p) {
        auto field_id = x.id();

        auto struct_type = typeID(p.parent().as<type::Struct>());
        if ( ! struct_type )
            return {};

        const auto& [module_id, struct_id] = *struct_type;

        return Identifier(util::join({module_id, struct_id, field_id}, "::"));
    }

    static std::optional<Identifier> getID(const declaration::Function& x, position_t p) {
        auto [a, b, c] = function_identifier(x, p);

        // `x` is a non-member function.
        if ( b.empty() )
            return Identifier(util::join({a, c}, "::"));

        // `x` is a member function.
        return Identifier(util::join({a, b, c}, "::"));
    }

    static std::optional<Identifier> getID(const operator_::struct_::MemberCall& x, position_t p) {
        if ( ! x.hasOp1() )
            return {};

        assert(x.hasOp0());

        auto struct_type = typeID(x.op0().type());
        if ( ! struct_type )
            return {};

        const auto& [module_id, struct_id] = *struct_type;

        const auto& member = x.op1().tryAs<expression::Member>();
        if ( ! member )
            return {};

        return Identifier(util::join({module_id, struct_id, member->id()}, "::"));
    }

    static std::optional<Identifier> getID(const operator_::function::Call& x, position_t p) {
        if ( ! x.hasOp0() )
            return {};

        auto id = x.op0().as<expression::ResolvedID>();

        auto module_id = id.id().sub(-2);
        auto fn_id = id.id().sub(-1);

        if ( module_id.empty() ) {
            // Functions declared in this module do not include a module name in their ID.
            if ( auto module = p.findParent<Module>() )
                module_id = module->get().id();
        }

        return Identifier(util::join({module_id, fn_id}, "::"));
    }

    void collect(Node& node) override {
        _stage = Stage::COLLECT;

        for ( auto i : this->walk(&node) )
            dispatch(i);
    }

    bool prune(Node& node) {
        switch ( _stage ) {
            case Stage::PRUNE_DECLS:
            case Stage::PRUNE_USES: break;
            case Stage::COLLECT: util::cannot_be_reached();
        }

        bool any_modification = false;

        while ( true ) {
            bool modified = false;
            for ( auto i : this->walk(&node) ) {
                if ( auto x = dispatch(i) )
                    modified = modified || *x;
            }

            if ( ! modified )
                break;

            any_modification = true;
        }

        return any_modification;
    }

    bool prune_uses(Node& node) override {
        _stage = Stage::PRUNE_USES;
        return prune(node);
    }

    bool prune_decls(Node& node) override {
        _stage = Stage::PRUNE_DECLS;
        return prune(node);
    }

    result_t operator()(const type::struct_::Field& x, position_t p) {
        if ( ! x.type().isA<type::Function>() )
            return false;

        auto function_id = getID(x, p);
        if ( ! function_id )
            return false;

        switch ( _stage ) {
            case Stage::COLLECT: {
                auto& function = _data[*function_id];

                auto fn = x.childsOfType<Function>();
                assert(fn.size() <= 1);

                // If the member declaration is marked `&always-emit` mark it as implemented.
                bool is_always_emit = static_cast<bool>(AttributeSet::find(x.attributes(), "&always-emit"));

                if ( is_always_emit )
                    function.defined = true;

                // If the member declaration includes a body mark it as implemented.
                if ( ! fn.empty() && fn.front().body() )
                    function.defined = true;

                // If the unit is wrapped in a type with a `&cxxname`
                // attribute its members are defined in C++ as well.
                auto type_ = p.findParent<declaration::Type>();
                bool is_cxx = type_ && AttributeSet::find(type_->get().attributes(), "&cxxname");

                if ( is_cxx )
                    function.defined = true;

                break;
            }

            case Stage::PRUNE_USES:
                // Nothing.
                break;

            case Stage::PRUNE_DECLS: {
                const auto& function = _data.at(*function_id);

                // Remove function methods without implementation.
                if ( ! function.defined ) {
                    HILTI_DEBUG(logging::debug::GlobalOptimizer,
                                util::fmt("removing field for unused method %s", *function_id));
                    removeNode(p);

                    return true;
                }

                break;
            }
        }

        return false;
    }

    result_t operator()(const declaration::Function& x, position_t p) {
        const auto function_id = getID(x, p);
        if ( ! function_id )
            return false;

        switch ( _stage ) {
            case Stage::COLLECT: {
                // Record this function if it is not already known.
                auto& function = _data[*function_id];

                const auto& fn = x.function();

                // If the declaration contains a function with a body mark the function as defined.
                if ( fn.body() )
                    function.defined = true;

                // If the declaration has a `&cxxname` it is defined in C++.
                else if ( AttributeSet::find(fn.attributes(), "&cxxname") ) {
                    function.defined = true;
                }

                // If the function declaration is marked `&always-emit` mark it as referenced.
                bool is_always_emit = AttributeSet::find(fn.attributes(), "&always-emit").has_value();

                if ( is_always_emit )
                    function.referenced = true;

                if ( fn.type().flavor() == type::function::Flavor::Hook )
                    function.hook = true;

                auto unit_type = scope::lookupID<declaration::Type>(fn.id().namespace_(), p, "type");

                switch ( fn.callingConvention() ) {
                    case function::CallingConvention::ExternNoSuspend:
                    case function::CallingConvention::Extern: {
                        // If the declaration is `extern` and the unit is `public`, the function
                        // is part of an externally visible API and potentially used elsewhere.

                        if ( unit_type ) {
                            if ( auto unit = unit_type->first->tryAs<declaration::Type>() )
                                function.referenced =
                                    function.referenced || unit->linkage() == declaration::Linkage::Public;
                        }
                        else
                            function.referenced = true;

                        break;
                    }
                    case function::CallingConvention::Standard:
                        // Nothing.
                        break;
                }

                switch ( x.linkage() ) {
                    case declaration::Linkage::PreInit:
                    case declaration::Linkage::Init:
                        // If the function is pre-init or init it could get
                        // invoked by the driver and should not be removed.
                        function.referenced = true;
                        break;
                    case declaration::Linkage::Private:
                    case declaration::Linkage::Public:
                        // Nothing.
                        break;
                    case declaration::Linkage::Struct: {
                        // If this is a method declaration check whether the type it referred
                        // to is still around; if not mark the function as an unreferenced
                        // non-hook so it gets removed for both plain methods and hooks.
                        if ( ! unit_type ) {
                            function.referenced = false;
                            function.hook = false;
                        }

                        break;
                    }
                }

                break;
            }

            case Stage::PRUNE_USES:
                // Nothing.
                break;

            case Stage::PRUNE_DECLS:
                const auto& function = _data.at(*function_id);

                if ( function.hook && ! function.defined ) {
                    HILTI_DEBUG(logging::debug::GlobalOptimizer,
                                util::fmt("removing declaration for unused hook function %s", *function_id));

                    removeNode(p);
                    return true;
                }

                if ( ! function.hook && ! function.referenced ) {
                    HILTI_DEBUG(logging::debug::GlobalOptimizer,
                                util::fmt("removing declaration for unused function %s", *function_id));

                    removeNode(p);
                    return true;
                }

                break;
        }

        return false;
    }

    result_t operator()(const operator_::struct_::MemberCall& x, position_t p) {
        auto function_id = getID(x, p);
        if ( ! function_id )
            return false;

        switch ( _stage ) {
            case Stage::COLLECT: {
                auto& function = _data[*function_id];

                function.referenced = true;

                return false;
            }

            case Stage::PRUNE_USES: {
                const auto& function = _data.at(*function_id);

                // Replace call node referencing unimplemented member function with default value.
                if ( ! function.defined ) {
                    if ( auto member = x.op1().tryAs<expression::Member>() )
                        if ( auto fn = member->memberType()->tryAs<type::Function>() ) {
                            HILTI_DEBUG(logging::debug::GlobalOptimizer,
                                        util::fmt("replacing call to unimplemented function %s with default value",
                                                  *function_id));

                            p.node = Expression(expression::Ctor(ctor::Default(fn->result().type())));

                            return true;
                        }
                }

                break;
            }

            case Stage::PRUNE_DECLS:
                // Nothing.
                break;
        }

        return false;
    }

    result_t operator()(const operator_::function::Call& call, position_t p) {
        auto function_id = getID(call, p);
        if ( ! function_id )
            return false;

        switch ( _stage ) {
            case Stage::COLLECT: {
                auto& function = _data[*function_id];

                function.referenced = true;
                return false;
            }

            case Stage::PRUNE_USES: {
                const auto& function = _data.at(*function_id);

                // Replace call node referencing unimplemented hook with default value.
                if ( function.hook && ! function.defined ) {
                    auto id = call.op0().as<expression::ResolvedID>();
                    if ( auto fn = id.declaration().tryAs<declaration::Function>() ) {
                        HILTI_DEBUG(logging::debug::GlobalOptimizer,
                                    util::fmt("replacing call to unimplemented function %s with default value",
                                              *function_id));

                        p.node = Expression(expression::Ctor(ctor::Default(fn->function().type().result().type())));

                        return true;
                    }
                }

                break;
            }

            case Stage::PRUNE_DECLS:
                // Nothing.
                break;
        }

        return false;
    }
};

struct TypeVisitor : OptimizerVisitor, visitor::PreOrder<bool, TypeVisitor> {
    std::map<ID, bool> _used;

    void collect(Node& node) override {
        _stage = Stage::COLLECT;

        for ( auto i : this->walk(&node) )
            dispatch(i);
    }

    bool prune_decls(Node& node) override {
        _stage = Stage::PRUNE_DECLS;

        bool any_modification = false;

        for ( auto i : this->walk(&node) )
            if ( auto x = dispatch(i) )
                any_modification = any_modification || *x;

        return any_modification;
    }

    result_t operator()(const declaration::Type& x, position_t p) {
        // We currently only handle type declarations for struct types or enum types.
        //
        // TODO(bbannier): Handle type aliases.
        if ( const auto& type = x.type(); ! (type.isA<type::Struct>() || type.isA<type::Enum>()) )
            return false;

        const auto type_id = x.typeID();

        if ( ! type_id )
            return false;

        switch ( _stage ) {
            case Stage::COLLECT:
                // Record the type if not already known. If the type is part of an external API record it as used.
                _used.insert({*type_id, x.linkage() == declaration::Linkage::Public});
                break;

            case Stage::PRUNE_USES: break;
            case Stage::PRUNE_DECLS:
                if ( ! _used.at(*type_id) ) {
                    HILTI_DEBUG(logging::debug::GlobalOptimizer, util::fmt("removing unused type '%s'", *type_id));

                    removeNode(p);

                    if ( auto module_ = p.findParent<Module>() )
                        // If this type was declared under a top-level module also clear the module declaration
                        // cache. The cache will get repopulated the next time the module's declarations are
                        // requested.
                        //
                        // TODO(bbannier): there has to be a better way to mutate the module.
                        const_cast<Module&>(module_->get()).clearCache();

                    return true;
                }

                break;
        }

        return false;
    }

    result_t operator()(const type::ResolvedID& x, position_t p) {
        switch ( _stage ) {
            case Stage::COLLECT: {
                const auto type = innermostType(x.type());

                const auto type_id = type.typeID();

                if ( ! type_id )
                    break;

                // Record this type as used.
                _used[*type_id] = true;
                break;
            }

            case Stage::PRUNE_USES:
            case Stage::PRUNE_DECLS:
                // Nothing.
                break;
        }

        return false;
    }

    result_t operator()(const expression::ResolvedID& x, position_t p) {
        switch ( _stage ) {
            case Stage::COLLECT: {
                const auto type = innermostType(x.type());

                const auto type_id = type.typeID();

                if ( ! type_id )
                    break;

                // Record this type as used.
                _used[*type_id] = true;

                break;
            }
            case Stage::PRUNE_USES:
            case Stage::PRUNE_DECLS:
                // Nothing.
                break;
        }

        return false;
    }

    result_t operator()(const expression::Type_& x, position_t p) {
        switch ( _stage ) {
            case Stage::COLLECT: {
                const auto type_id = x.typeValue().typeID();

                if ( ! type_id )
                    break;

                // Record this type as used.
                _used[*type_id] = true;
                break;
            }

            case Stage::PRUNE_USES:
            case Stage::PRUNE_DECLS:
                // Nothing.
                break;
        }

        return false;
    }

    result_t operator()(const type::ValueReference& x, position_t p) {
        switch ( _stage ) {
            case Stage::COLLECT: {
                const auto& type_id = x.typeID();

                if ( ! type_id )
                    break;

                // Record this type as used.
                _used[*type_id] = true;
                break;
            }
            case Stage::PRUNE_USES:
            case Stage::PRUNE_DECLS:
                // Nothing.
                break;
        }

        return false;
    }
};

struct ConstantFoldingVisitor : OptimizerVisitor, visitor::PreOrder<bool, ConstantFoldingVisitor> {
    // TODO(bbannier): Index constants by their canonical ID once it is
    // available. We should also be able to remove `Node::rid` at that point.
    std::map<uint64_t, bool> _constants;

    void collect(Node& node) override {
        _stage = Stage::COLLECT;

        for ( auto i : this->walk(&node) )
            dispatch(i);
    }

    bool prune_uses(Node& node) override {
        _stage = Stage::PRUNE_USES;

        bool any_modification = false;

        while ( true ) {
            bool modified = false;
            for ( auto i : this->walk(&node) ) {
                if ( auto x = dispatch(i) )
                    modified = *x || modified;
            }

            if ( ! modified )
                break;

            any_modification = true;
        }

        return any_modification;
    }

    bool operator()(const declaration::GlobalVariable& x, position_t p) {
        // We only work on boolean constants.
        if ( ! (x.isConstant() || x.type() == type::Bool()) )
            return false;

        switch ( _stage ) {
            case Stage::COLLECT: {
                const auto& init = x.init();
                assert(init);

                if ( auto ctor = init.value().tryAs<expression::Ctor>() )
                    if ( auto bool_ = ctor->ctor().tryAs<ctor::Bool>() )
                        _constants[p.node.rid()] = bool_->value();

                break;
            }

            case Stage::PRUNE_USES:
            case Stage::PRUNE_DECLS: break;
        }

        return false;
    }

    bool operator()(const expression::ResolvedID& x, position_t p) {
        switch ( _stage ) {
            case Stage::COLLECT:
            case Stage::PRUNE_DECLS: return false;
            case Stage::PRUNE_USES: {
                auto rid = x.rid();

                if ( const auto& constant = _constants.find(rid); constant != _constants.end() ) {
                    if ( x.type() == type::Bool() ) {
                        HILTI_DEBUG(logging::debug::GlobalOptimizer, util::fmt("inlining constant '%s'", x.id()));

                        replaceNode(p, builder::bool_(constant->second));

                        return true;
                    }
                }
            }
        }

        return false;
    }

    bool operator()(const statement::If& x, position_t p) {
        switch ( _stage ) {
            case Stage::COLLECT:
            case Stage::PRUNE_DECLS: return false;
            case Stage::PRUNE_USES: {
                if ( auto expression = x.condition()->tryAs<expression::Ctor>() )
                    if ( auto bool_ = expression->ctor().tryAs<ctor::Bool>() ) {
                        if ( auto else_ = x.false_() ) {
                            if ( ! bool_->value() ) {
                                replaceNode(p, *else_);
                                return true;
                            }
                            else {
                                replaceNode(p, statement::If::removeElse(x));
                                return true;
                            }
                        }
                        else {
                            if ( ! bool_->value() ) {
                                removeNode(p);
                                return true;
                            }
                            else {
                                replaceNode(p, x.true_());
                                return true;
                            }
                        }

                        return false;
                    };
            }
        }

        return false;
    }
};

// This visitor collects requirement attributes in the AST and toggles unused features.
struct FeatureRequirementsVisitor : visitor::PreOrder<void, FeatureRequirementsVisitor> {
    // Lookup table for feature name -> required.
    using Features = std::map<std::string, bool>;

    // Lookup table for typename -> features.
    std::map<ID, Features> _features;

    enum class Stage { COLLECT, TRANSFORM };
    Stage _stage = Stage::COLLECT;

    void collect(Node& node) {
        _stage = Stage::COLLECT;

        for ( auto i : this->walk(&node) )
            dispatch(i);
    }

    void transform(Node& node) {
        _stage = Stage::TRANSFORM;

        for ( auto i : this->walk(&node) )
            dispatch(i);
    }

    void operator()(const declaration::GlobalVariable& x, position_t p) {
        const auto& id = x.id();

        // We only work on feature flags named `__feat*`.
        if ( ! util::startsWith(id, "__feat") )
            return;

        const auto& tokens = util::split(id, "%");
        assert(tokens.size() == 3);

        // The type name is encoded in the variable name with `::` replaced by `__`.
        const auto& typeID = ID(util::replace(tokens[1], "__", "::"));
        const auto& feature = tokens[2];

        switch ( _stage ) {
            case Stage::COLLECT: {
                // Record the feature as unused for the type if it was not already recorded.
                _features[typeID].insert({feature, false});
                break;
            }

            case Stage::TRANSFORM: {
                const auto required = _features.at(typeID).at(feature);
                const auto value = x.init().value().as<expression::Ctor>().ctor().as<ctor::Bool>().value();

                if ( required != value ) {
                    HILTI_DEBUG(logging::debug::GlobalOptimizer,
                                util::fmt("disabling feature '%s' of type '%s' since it is not used", feature, typeID));

                    auto new_x = declaration::GlobalVariable::setInit(x, builder::bool_(false));
                    replaceNode(p, new_x);

                    if ( auto module_ = p.findParent<Module>() )
                        // If this global was declared under a top-level module also clear the module declaration
                        // cache. The cache will get repopulated the next time the module's declarations are
                        // requested.
                        //
                        // TODO(bbannier): there has to be a better way to mutate the module.
                        const_cast<Module&>(module_->get()).clearCache();
                }

                break;
            }
        }
    }

    // Helper function to compute the set of feature flags wrapping the given position.
    static std::map<ID, std::set<std::string>> conditionalFeatures(position_t p) {
        // Compute a list of features this use does not activate.
        // Generated feature-dependent code is always under
        // conditionals `if (__feat%XYZ%FEATURE) ...` so get all
        // `FEATURE` for all parents which match this pattern.
        std::map<ID, std::set<std::string>> result;

        for ( const auto& parent : p.path ) {
            if ( ! parent.node.isA<statement::If>() )
                continue;

            const auto& if_ = parent.node.as<statement::If>();
            const auto condition = if_.condition();
            if ( ! condition )
                continue;

            auto rid = condition->tryAs<expression::ResolvedID>();
            if ( ! rid )
                continue;

            // Split away the module part of the resolved ID.
            auto id = util::split1(rid->id(), "::").second;

            if ( ! util::startsWith(id, "__feat") )
                continue;

            const auto& tokens = util::split(id, "%");
            assert(tokens.size() == 3);

            const auto type_id = ID(util::replace(tokens[1], "__", "::"));
            const auto& feature = tokens[2];

            result[std::move(type_id)].insert(feature);
        }

        return result;
    }

    void handleMemberAccess(const expression::ResolvedOperator& x, position_t p) {
        switch ( _stage ) {
            case Stage::COLLECT: {
                auto type_ = x.op0().type();
                while ( type::isReferenceType(type_) )
                    type_ = type_.dereferencedType();

                auto typeID = type_.typeID();
                if ( ! typeID )
                    return;

                auto member = x.op1().template tryAs<expression::Member>();
                if ( ! member )
                    return;

                auto lookup = scope::lookupID<declaration::Type>(*typeID, p, "type");
                if ( ! lookup )
                    return;

                auto type = lookup->first->template as<declaration::Type>();
                auto struct_ = type.type().template tryAs<type::Struct>();
                if ( ! struct_ )
                    return;

                auto field = struct_->field(member->id());
                if ( ! field )
                    return;

                const auto ignored_features = conditionalFeatures(p);

                for ( const auto& requirement : AttributeSet::findAll(field->attributes(), "&needed-by-feature") ) {
                    const auto feature = *requirement.template valueAs<std::string>();

                    // Enable the required feature if it is not ignored here.
                    if ( ! ignored_features.count(*typeID) || ! ignored_features.at(*typeID).count(feature) )
                        _features[*typeID][feature] = true;
                }

                break;
            }
            case Stage::TRANSFORM:
                // Nothing.
                break;
        }
    }

    void operator()(const operator_::struct_::MemberConst& x, position_t p) { return handleMemberAccess(x, p); }
    void operator()(const operator_::struct_::MemberNonConst& x, position_t p) { return handleMemberAccess(x, p); }
};

void GlobalOptimizer::run() {
    util::timing::Collector _("hilti/compiler/global-optimizer");

    // Create a full list of units to run on. This includes both the units
    // explicitly passed on construction as well as their dependencies.
    auto units = [&]() {
        // We initially store the list as a `set` to ensure uniqueness, but
        // convert to a `vector` so we can mutate entries while iterating.
        auto NodeRefCmp = [](const NodeRef& lhs, const NodeRef& rhs) { return lhs->identity() < rhs->identity(); };
        std::set<NodeRef, decltype(NodeRefCmp)> units(NodeRefCmp);

        for ( auto& unit : *_units ) {
            units.insert(NodeRef(unit.imported(unit.id())));

            for ( const auto& dep : _ctx->lookupDependenciesForModule(unit.id()) )
                units.insert(NodeRef(unit.imported(dep.index.id)));
        }

        return std::vector<NodeRef>{units.begin(), units.end()};
    }();

    const auto passes__ = rt::getenv("HILTI_OPTIMIZER_PASSES");
    const auto passes_ =
        passes__ ? std::optional(util::split(*passes__, ":")) : std::optional<std::vector<std::string>>();
    auto passes = passes_ ? std::optional(std::set<std::string>(passes_->begin(), passes_->end())) :
                            std::optional<std::set<std::string>>();

    if ( ! passes || passes->count("feature_requirements") ) {
        // The `FeatureRequirementsVisitor` enables or disables code
        // paths and needs to be run before all other passes since
        // it needs to see the code before any optimization edits.
        FeatureRequirementsVisitor v;
        for ( auto& unit : units )
            v.collect(*unit);

        for ( auto& unit : units )
            v.transform(*unit);
    }

    const std::map<std::string, std::function<std::unique_ptr<OptimizerVisitor>()>> creators =
        {{"constant_folding", []() { return std::make_unique<ConstantFoldingVisitor>(); }},
         {"functions", []() { return std::make_unique<FunctionVisitor>(); }},
         {"types", []() { return std::make_unique<TypeVisitor>(); }}};

    // If no user-specified passes are given enable all of them.
    if ( ! passes ) {
        passes = std::set<std::string>();
        for ( const auto& [pass, _] : creators )
            passes->insert(pass);
    }

    while ( true ) {
        bool modified = false;

        // NOTE: We do not use `util::transform` here to guarantee a consistent order of the visitors.
        std::vector<std::unique_ptr<OptimizerVisitor>> vs;
        vs.reserve(passes->size());
        for ( const auto& pass : *passes )
            if ( creators.count(pass) )
                vs.push_back(creators.at(pass)());

        for ( auto& v : vs ) {
            for ( auto& unit : units )
                v->collect(*unit);

            for ( auto& unit : units )
                modified = v->prune_uses(*unit) || modified;

            for ( auto& unit : units )
                modified = v->prune_decls(*unit) || modified;
        };

        if ( ! modified )
            break;
    }

    // Clear cached information which might become outdated due to edits.
    for ( auto& unit : units ) {
        for ( auto i : hilti::visitor::PreOrder<>().walk(&*unit) ) {
            i.node.clearScope();

            if ( i.node.isA<hilti::Module>() )
                i.node.as<Module>().preserved().clear();
        }
    }
}

} // namespace hilti
