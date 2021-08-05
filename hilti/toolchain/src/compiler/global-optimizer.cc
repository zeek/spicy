// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#include "hilti/compiler/global-optimizer.h"

#include <algorithm>
#include <optional>
#include <tuple>
#include <unordered_set>
#include <utility>

#include <hilti/ast/ctors/default.h>
#include <hilti/ast/declarations/function.h>
#include <hilti/ast/declarations/imported-module.h>
#include <hilti/ast/detail/visitor.h>
#include <hilti/ast/expressions/ctor.h>
#include <hilti/ast/node.h>
#include <hilti/ast/scope-lookup.h>
#include <hilti/ast/statements/block.h>
#include <hilti/ast/types/struct.h>
#include <hilti/base/logger.h>
#include <hilti/base/timing.h>
#include <hilti/base/util.h>

namespace hilti {

namespace logging::debug {
inline const DebugStream GlobalOptimizer("global-optimizer");
} // namespace logging::debug

enum class Stage { COLLECT, PRUNE_USES, PRUNE_DECLS };

struct FunctionVisitor : visitor::PreOrder<bool, FunctionVisitor> {
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
    static void replaceNode(position_t& p, T&& n) {
        p.node = std::forward<T>(n);
    }

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

    static void removeNode(position_t& p) { replaceNode(p, node::none); }

    Stage _stage = Stage::COLLECT;

    void collect(Node& node) {
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

    bool prune_uses(Node& node) {
        _stage = Stage::PRUNE_USES;
        return prune(node);
    }

    bool prune_decls(Node& node) {
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

                switch ( fn.callingConvention() ) {
                    case function::CallingConvention::ExternNoSuspend:
                    case function::CallingConvention::Extern: {
                        // If the declaration is `extern` and the unit is `public`, the function
                        // is part of an externally visible API and potentially used elsewhere.

                        if ( auto unit_type = scope::lookupID<declaration::Type>(fn.id().namespace_(), p, "type") ) {
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
                    case declaration::Linkage::Struct:
                        // Nothing.
                        break;
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

    while ( true ) {
        bool modified = false;

        FunctionVisitor function_visitor;

        for ( auto& unit : units )
            function_visitor.collect(*unit);

        for ( auto& unit : units )
            modified = modified || function_visitor.prune_uses(*unit);

        for ( auto& unit : units )
            modified = modified || function_visitor.prune_decls(*unit);

        if ( ! modified )
            break;
    }

    // The edits performed by the optimizer might invalidate scopes which after
    // optimizations might contain references to now removed data. We
    // unconditionally clear scopes to make sure to remove any effects from
    // scopes.
    for ( auto& unit : units ) {
        for ( auto i : hilti::visitor::PreOrder<>().walk(&*unit) )
            i.node.clearScope();
    }
}

} // namespace hilti
