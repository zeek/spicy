// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include "hilti/compiler/optimizer.h"

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
#include <hilti/ast/expressions/logical-and.h>
#include <hilti/ast/expressions/logical-not.h>
#include <hilti/ast/expressions/logical-or.h>
#include <hilti/ast/expressions/ternary.h>
#include <hilti/ast/node.h>
#include <hilti/ast/scope-lookup.h>
#include <hilti/ast/statements/block.h>
#include <hilti/ast/type.h>
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
inline const DebugStream Optimizer("optimizer");
inline const DebugStream OptimizerCollect("optimizer-collect");
} // namespace logging::debug

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
    Module* _current_module = nullptr;

    template<typename Position>
    void replaceNode(Position& p, const Node& replacement) {
        assert(_current_module);
        _current_module->preserve(p.node);
        p.node = replacement;
    }

    template<typename Position>
    void removeNode(Position& p) {
        replaceNode(p, node::none);
    }

    virtual ~OptimizerVisitor() = default;
    virtual void collect(Node&) {}
    virtual bool prune_uses(Node&) { return false; }
    virtual bool prune_decls(Node&) { return false; }
};

struct FunctionVisitor : OptimizerVisitor, visitor::PreOrder<bool, FunctionVisitor> {
    struct Uses {
        bool hook = false;
        bool defined = false;
        bool referenced = false;
    };

    // Lookup table for feature name -> required.
    using Features = std::map<std::string, bool>;

    // Lookup table for typename -> features.
    std::map<ID, Features> _features;

    std::map<ID, Uses> _data;

    void collect(Node& node) override {
        _stage = Stage::COLLECT;

        while ( true ) {
            bool collect_again = false;

            for ( auto i : this->walk(&node) )
                if ( auto x = dispatch(i) )
                    collect_again = collect_again || *x;

            if ( logger().isEnabled(logging::debug::OptimizerCollect) ) {
                HILTI_DEBUG(logging::debug::OptimizerCollect, "functions:");
                for ( const auto& [id, uses] : _data )
                    HILTI_DEBUG(logging::debug::OptimizerCollect,
                                util::fmt("    %s: defined=%d referenced=%d hook=%d", id, uses.defined, uses.referenced,
                                          uses.hook));
            }

            if ( ! collect_again )
                break;
        }
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

    result_t operator()(const Module& m, position_t p) {
        _current_module = &p.node.as<Module>();
        return false;
    }

    result_t operator()(const declaration::Field& x, position_t p) {
        if ( ! x.type().isA<type::Function>() )
            return false;

        if ( ! p.parent().isA<type::Struct>() )
            return {};

        const auto& function_id = x.canonicalID();
        assert(function_id);

        switch ( _stage ) {
            case Stage::COLLECT: {
                auto& function = _data[function_id];

                auto fn = x.childrenOfType<Function>();
                assert(fn.size() <= 1);

                // If the member declaration is marked `&always-emit` mark it as implemented.
                bool is_always_emit = static_cast<bool>(AttributeSet::find(x.attributes(), "&always-emit"));

                if ( is_always_emit )
                    function.defined = true;

                // If the member declaration includes a body mark it as implemented.
                if ( ! fn.empty() && fn.begin()->body() )
                    function.defined = true;

                // If the unit is wrapped in a type with a `&cxxname`
                // attribute its members are defined in C++ as well.
                auto type_ = p.findParent<declaration::Type>();
                bool is_cxx = type_ && AttributeSet::find(type_->get().attributes(), "&cxxname");

                if ( is_cxx )
                    function.defined = true;

                if ( auto type = type_ )
                    for ( const auto& requirement : AttributeSet::findAll(x.attributes(), "&needed-by-feature") ) {
                        auto feature = *requirement.valueAsString();

                        // If no feature constants were collected yet, reschedule us for the next collection pass.
                        //
                        // NOTE: If we emit a `&needed-by-feature` attribute we also always emit a matching feature
                        // constant, so eventually at this point we will see at least one feature constant.
                        if ( _features.empty() )
                            return true;

                        auto it = _features.find(type->get().canonicalID());
                        if ( it == _features.end() )
                            // No feature requirements known for type.
                            continue;

                        function.referenced = function.referenced || it->second.at(feature);
                    }

                break;
            }

            case Stage::PRUNE_USES:
                // Nothing.
                break;

            case Stage::PRUNE_DECLS: {
                const auto& function = _data.at(function_id);

                // Remove function methods without implementation.
                if ( ! function.defined && ! function.referenced ) {
                    HILTI_DEBUG(logging::debug::Optimizer,
                                util::fmt("removing field for unused method %s", function_id));
                    removeNode(p);

                    return true;
                }

                break;
            }
        }

        return false;
    }

    result_t operator()(const declaration::Function& x, position_t p) {
        const auto& function_id = x.canonicalID();
        assert(function_id);

        switch ( _stage ) {
            case Stage::COLLECT: {
                // Record this function if it is not already known.
                auto& function = _data[function_id];

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

                // For implementation of methods check whether the method
                // should only be emitted when certain features are active.
                if ( auto parent = x.parent() )
                    for ( const auto& requirement : AttributeSet::findAll(fn.attributes(), "&needed-by-feature") ) {
                        auto feature = *requirement.valueAsString();

                        // If no feature constants were collected yet, reschedule us for the next collection pass.
                        //
                        // NOTE: If we emit a `&needed-by-feature` attribute we also always emit a matching feature
                        // constant, so eventually at this point we will see at least one feature constant.
                        if ( _features.empty() )
                            return true;

                        auto it = _features.find(parent->canonicalID());
                        if ( it == _features.end() )
                            // No feature requirements known for type.
                            continue;

                        // Mark the function as referenced if it is needed by an active feature.
                        function.referenced = function.referenced || it->second.at(feature);
                    }

                if ( fn.ftype().flavor() == type::function::Flavor::Hook )
                    function.hook = true;

                const auto parent = x.parent();

                switch ( fn.callingConvention() ) {
                    case function::CallingConvention::ExternNoSuspend:
                    case function::CallingConvention::Extern: {
                        // If the declaration is `extern` and the unit is `public`, the function
                        // is part of an externally visible API and potentially used elsewhere.

                        if ( parent )
                            function.referenced =
                                function.referenced || parent->linkage() == declaration::Linkage::Public;
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
                        if ( ! parent ) {
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
                const auto& function = _data.at(function_id);

                if ( function.hook && ! function.defined ) {
                    HILTI_DEBUG(logging::debug::Optimizer,
                                util::fmt("removing declaration for unused hook function %s", function_id));

                    removeNode(p);
                    return true;
                }

                if ( ! function.hook && ! function.referenced ) {
                    HILTI_DEBUG(logging::debug::Optimizer,
                                util::fmt("removing declaration for unused function %s", function_id));

                    removeNode(p);
                    return true;
                }

                break;
        }

        return false;
    }

    result_t operator()(const operator_::struct_::MemberCall& x, position_t p) {
        if ( ! x.hasOp1() )
            return false;

        assert(x.hasOp0());

        auto type = x.op0().type();

        auto struct_ = type.tryAs<type::Struct>();
        if ( ! struct_ )
            return false;

        const auto& member = x.op1().tryAs<expression::Member>();
        if ( ! member )
            return false;

        auto field = struct_->field(member->id());
        if ( ! field )
            return false;

        const auto& function_id = field->canonicalID();

        if ( ! function_id )
            return false;

        switch ( _stage ) {
            case Stage::COLLECT: {
                auto& function = _data[function_id];

                function.referenced = true;

                return false;
            }

            case Stage::PRUNE_USES: {
                const auto& function = _data.at(function_id);

                // Replace call node referencing unimplemented member function with default value.
                if ( ! function.defined ) {
                    if ( auto member = x.op1().tryAs<expression::Member>() )
                        if ( auto fn = member->type().tryAs<type::Function>() ) {
                            HILTI_DEBUG(logging::debug::Optimizer,
                                        util::fmt("replacing call to unimplemented function %s with default value",
                                                  function_id));

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
        if ( ! call.hasOp0() )
            return {};

        auto function_id = call.op0().as<expression::ResolvedID>().declaration().canonicalID();
        assert(function_id);

        switch ( _stage ) {
            case Stage::COLLECT: {
                auto& function = _data[function_id];

                function.referenced = true;
                return false;
            }

            case Stage::PRUNE_USES: {
                const auto& function = _data.at(function_id);

                // Replace call node referencing unimplemented hook with default value.
                if ( function.hook && ! function.defined ) {
                    auto id = call.op0().as<expression::ResolvedID>();
                    if ( auto fn = id.declaration().tryAs<declaration::Function>() ) {
                        HILTI_DEBUG(logging::debug::Optimizer,
                                    util::fmt("replacing call to unimplemented function %s with default value",
                                              function_id));

                        p.node = Expression(expression::Ctor(ctor::Default(fn->function().ftype().result().type())));

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

    result_t operator()(const declaration::Constant& x, position_t p) {
        switch ( _stage ) {
            case Stage::COLLECT: {
                std::optional<bool> value;
                if ( auto ctor = x.value().tryAs<expression::Ctor>() )
                    if ( auto bool_ = ctor->ctor().tryAs<ctor::Bool>() )
                        value = bool_->value();

                if ( ! value )
                    break;

                const auto& id = x.id();

                // We only work on feature flags named `__feat*`.
                if ( ! util::startsWith(id, "__feat") )
                    break;

                const auto& tokens = util::split(id, "%");
                assert(tokens.size() == 3);

                // The type name is encoded in the variable name with `::` replaced by `__`.
                const auto& typeID = ID(util::replace(tokens[1], "__", "::"));
                const auto& feature = tokens[2];

                _features[typeID].insert({feature, *value});
                break;
            }

            case Stage::PRUNE_USES:
            case Stage::PRUNE_DECLS: break;
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

        if ( logger().isEnabled(logging::debug::OptimizerCollect) ) {
            HILTI_DEBUG(logging::debug::OptimizerCollect, "types:");
            for ( const auto& [id, used] : _used )
                HILTI_DEBUG(logging::debug::OptimizerCollect, util::fmt("    %s: used=%d", id, used));
        }
    }

    bool prune_decls(Node& node) override {
        _stage = Stage::PRUNE_DECLS;

        bool any_modification = false;

        for ( auto i : this->walk(&node) )
            if ( auto x = dispatch(i) )
                any_modification = any_modification || *x;

        return any_modification;
    }

    result_t operator()(const Module& m, position_t p) {
        _current_module = &p.node.as<Module>();
        return false;
    }

    result_t operator()(const declaration::Field& x, position_t p) {
        switch ( _stage ) {
            case Stage::COLLECT: {
                const auto type_id = x.type().typeID();

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
                    HILTI_DEBUG(logging::debug::Optimizer, util::fmt("removing unused type '%s'", *type_id));
                    removeNode(p);
                    return true;
                }

                break;
        }

        return false;
    }

    result_t operator()(const Type& type, position_t p) {
        if ( p.parent().isA<declaration::Type>() )
            return false;

        switch ( _stage ) {
            case Stage::COLLECT: {
                if ( const auto& type_id = type.typeID() )
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

                const auto& type_id = type.typeID();

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

    result_t operator()(const declaration::Function& x, position_t p) {
        switch ( _stage ) {
            case Stage::COLLECT: {
                if ( auto parent = x.parent() ) {
                    // If this type is referenced by a function declaration it is used.
                    _used[parent->canonicalID()] = true;
                    break;
                }
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
};

struct ConstantFoldingVisitor : OptimizerVisitor, visitor::PreOrder<bool, ConstantFoldingVisitor> {
    std::map<ID, bool> _constants;

    void collect(Node& node) override {
        _stage = Stage::COLLECT;

        for ( auto i : this->walk(&node) )
            dispatch(i);

        if ( logger().isEnabled(logging::debug::OptimizerCollect) ) {
            HILTI_DEBUG(logging::debug::OptimizerCollect, "constants:");
            std::vector<std::string> xs;
            for ( const auto& [id, value] : _constants )
                HILTI_DEBUG(logging::debug::OptimizerCollect, util::fmt("    %s: value=%d", id, value));
        }
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

    result_t operator()(const Module& m, position_t p) {
        _current_module = &p.node.as<Module>();
        return false;
    }

    bool operator()(const declaration::Constant& x, position_t p) {
        if ( x.type() != type::Bool() )
            return false;

        const auto& id = x.canonicalID();
        assert(id);

        switch ( _stage ) {
            case Stage::COLLECT: {
                if ( auto ctor = x.value().tryAs<expression::Ctor>() )
                    if ( auto bool_ = ctor->ctor().tryAs<ctor::Bool>() )
                        _constants[id] = bool_->value();

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
                auto id = x.declaration().canonicalID();
                assert(id);

                if ( const auto& constant = _constants.find(id); constant != _constants.end() ) {
                    if ( x.type() == type::Bool() ) {
                        HILTI_DEBUG(logging::debug::Optimizer, util::fmt("inlining constant '%s'", x.id()));

                        replaceNode(p, builder::bool_(constant->second));

                        return true;
                    }
                }
            }
        }

        return false;
    }

    std::optional<bool> tryAsBoolLiteral(const Expression& x) {
        if ( auto expression = x.tryAs<expression::Ctor>() )
            if ( auto bool_ = expression->ctor().tryAs<ctor::Bool>() )
                return {bool_->value()};

        return {};
    }

    bool operator()(const statement::If& x, position_t p) {
        switch ( _stage ) {
            case Stage::COLLECT:
            case Stage::PRUNE_DECLS: return false;
            case Stage::PRUNE_USES: {
                if ( auto bool_ = tryAsBoolLiteral(x.condition().value()) ) {
                    if ( auto else_ = x.false_() ) {
                        if ( ! bool_.value() ) {
                            replaceNode(p, *else_);
                            return true;
                        }
                        else {
                            p.node.as<statement::If>().removeFalse();
                            return true;
                        }
                    }
                    else {
                        if ( ! bool_.value() ) {
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

    bool operator()(const expression::Ternary& x, position_t p) {
        switch ( _stage ) {
            case OptimizerVisitor::Stage::COLLECT:
            case OptimizerVisitor::Stage::PRUNE_DECLS: return false;
            case OptimizerVisitor::Stage::PRUNE_USES: {
                if ( auto bool_ = tryAsBoolLiteral(x.condition()) ) {
                    if ( *bool_ )
                        replaceNode(p, x.true_());
                    else
                        replaceNode(p, x.false_());

                    return true;
                }
            }
        }

        return false;
    }

    bool operator()(const expression::LogicalOr& x, position_t p) {
        switch ( _stage ) {
            case Stage::COLLECT:
            case Stage::PRUNE_DECLS: break;
            case Stage::PRUNE_USES: {
                auto lhs = tryAsBoolLiteral(x.op0());
                auto rhs = tryAsBoolLiteral(x.op1());

                if ( lhs && rhs ) {
                    replaceNode(p, builder::bool_(lhs.value() || rhs.value()));
                    return true;
                }
            }
        };

        return false;
    }

    bool operator()(const expression::LogicalAnd& x, position_t p) {
        switch ( _stage ) {
            case Stage::COLLECT:
            case Stage::PRUNE_DECLS: break;
            case Stage::PRUNE_USES: {
                auto lhs = tryAsBoolLiteral(x.op0());
                auto rhs = tryAsBoolLiteral(x.op1());

                if ( lhs && rhs ) {
                    replaceNode(p, builder::bool_(lhs.value() && rhs.value()));
                    return true;
                }
            }
        };

        return false;
    }

    bool operator()(const expression::LogicalNot& x, position_t p) {
        switch ( _stage ) {
            case Stage::COLLECT:
            case Stage::PRUNE_DECLS: break;
            case Stage::PRUNE_USES: {
                if ( auto op = tryAsBoolLiteral(x.expression()) ) {
                    replaceNode(p, builder::bool_(! op.value()));
                    return true;
                }
            }
        };

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

        if ( logger().isEnabled(logging::debug::OptimizerCollect) ) {
            HILTI_DEBUG(logging::debug::OptimizerCollect, "feature requirements:");
            for ( const auto& [id, features] : _features ) {
                std::stringstream ss;
                ss << "    " << id << ':';
                for ( const auto& [feature, enabled] : features )
                    ss << util::fmt(" %s=%d", feature, enabled);
                HILTI_DEBUG(logging::debug::OptimizerCollect, ss.str());
            }
        }
    }

    void transform(Node& node) {
        _stage = Stage::TRANSFORM;

        for ( auto i : this->walk(&node) )
            dispatch(i);
    }

    void operator()(const declaration::Constant& x, position_t p) {
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
                const auto value = x.value().as<expression::Ctor>().ctor().as<ctor::Bool>().value();

                if ( required != value ) {
                    HILTI_DEBUG(logging::debug::Optimizer,
                                util::fmt("disabling feature '%s' of type '%s' since it is not used", feature, typeID));

                    p.node.as<declaration::Constant>().setValue(builder::bool_(false));
                }

                break;
            }
        }
    }

    void operator()(const operator_::function::Call& x, position_t p) {
        switch ( _stage ) {
            case Stage::COLLECT: {
                // Collect parameter requirements from the declaration of the called function.
                std::vector<std::set<std::string>> requirements;

                auto rid = x.op0().tryAs<expression::ResolvedID>();
                if ( ! rid )
                    return;

                const auto& fn = rid->declaration().tryAs<declaration::Function>();
                if ( ! fn )
                    return;

                for ( const auto& parameter : fn->function().ftype().parameters() ) {
                    // The requirements of this parameter.
                    std::set<std::string> reqs;

                    for ( const auto& requirement :
                          AttributeSet::findAll(parameter.attributes(), "&requires-type-feature") ) {
                        auto feature = *requirement.valueAsString();
                        reqs.insert(std::move(feature));
                    }

                    requirements.push_back(std::move(reqs));
                }

                const auto ignored_features = conditionalFeatures(p);

                // Collect the types of parameters from the actual arguments.
                // We cannot get this information from the declaration since it
                // might use `any` types. Correlate this with the requirement
                // information collected previously and update the global list
                // of feature requirements.
                std::size_t i = 0;
                for ( const auto& arg : x.op1().as<expression::Ctor>().ctor().as<ctor::Tuple>().value() ) {
                    // Instead of applying the type requirement only to the
                    // potentially unref'd passed value's type, we also apply
                    // it to the element type of list args. Since this
                    // optimizer pass removes code worst case this could lead
                    // to us optimizing less.
                    auto type = innermostType(arg.type());

                    // Ignore arguments types without type ID (e.g., builtin types).
                    const auto& typeID = type.typeID();
                    if ( ! typeID ) {
                        ++i;
                        continue;
                    }

                    for ( const auto& requirement : requirements[i] ) {
                        if ( ! ignored_features.count(*typeID) || ! ignored_features.at(*typeID).count(requirement) )
                            // Enable the required feature.
                            _features[*typeID][requirement] = true;
                    }

                    ++i;
                }
            }

            case Stage::TRANSFORM: {
                // Nothing.
                break;
            }
        }
    }

    void operator()(const operator_::struct_::MemberCall& x, position_t p) {
        switch ( _stage ) {
            case Stage::COLLECT: {
                auto type = x.op0().type();
                while ( type::isReferenceType(type) )
                    type = type.dereferencedType();

                const auto struct_ = type.tryAs<type::Struct>();
                if ( ! struct_ )
                    break;

                const auto& member = x.op1().as<expression::Member>();

                const auto field = struct_->field(member.id());
                if ( ! field )
                    break;

                const auto ignored_features = conditionalFeatures(p);

                // Check if access to the field has type requirements.
                if ( auto type_id = type.typeID() )
                    for ( const auto& requirement : AttributeSet::findAll(field->attributes(), "&needed-by-feature") ) {
                        const auto feature = *requirement.valueAsString();
                        if ( ! ignored_features.count(*type_id) || ! ignored_features.at(*type_id).count(feature) )
                            // Enable the required feature.
                            _features[*type_id][*requirement.valueAsString()] = true;
                    }

                // Check if call imposes requirements on any of the types of the arguments.
                if ( auto fn = member.type().tryAs<type::Function>() ) {
                    const auto parameters = fn->parameters();
                    if ( parameters.empty() )
                        break;

                    const auto& args = x.op2().as<expression::Ctor>().ctor().as<ctor::Tuple>().value();

                    for ( size_t i = 0; i < parameters.size(); ++i ) {
                        // Since the declaration might use `any` types, get the
                        // type of the parameter from the passed argument.

                        // Instead of applying the type requirement only to the
                        // potentially unref'd passed value's type, we also apply
                        // it to the element type of list args. Since this
                        // optimizer pass removes code worst case this could lead
                        // to us optimizing less.
                        const auto type = innermostType(args[i].type());

                        const auto& param = parameters[i];

                        if ( auto type_id = type.typeID() )
                            for ( const auto& requirement :
                                  AttributeSet::findAll(param.attributes(), "&requires-type-feature") ) {
                                const auto feature = *requirement.valueAsString();
                                if ( ! ignored_features.count(*type_id) ||
                                     ! ignored_features.at(*type_id).count(feature) ) {
                                    // Enable the required feature.
                                    _features[*type_id][feature] = true;
                                }
                            }
                    }
                }

                break;
            }
            case Stage::TRANSFORM:
                // Nothing.
                break;
        }
    }

    // Helper function to compute all feature flags participating in an
    // condition. Feature flags are always combined with logical `or`.
    static void featureFlagsFromCondition(const Expression& condition, std::map<ID, std::set<std::string>>& result) {
        // Helper to extract `(ID, feature)` from a feature constant.
        auto idFeatureFromConstant = [](const ID& featureConstant) -> std::optional<std::pair<ID, std::string>> {
            // Split away the module part of the resolved ID.
            auto id = util::split1(featureConstant, "::").second;

            if ( ! util::startsWith(id, "__feat") )
                return {};

            const auto& tokens = util::split(id, "%");
            assert(tokens.size() == 3);

            auto type_id = ID(util::replace(tokens[1], "__", "::"));
            const auto& feature = tokens[2];

            return {{type_id, feature}};
        };

        if ( auto rid = condition.tryAs<expression::ResolvedID>() ) {
            if ( auto id_feature = idFeatureFromConstant(rid->id()) )
                result[std::move(id_feature->first)].insert(std::move(id_feature->second));
        }

        // If we did not find a feature constant in the conditional, we
        // could also be dealing with a `OR` of feature constants.
        else if ( auto or_ = condition.tryAs<expression::LogicalOr>() ) {
            featureFlagsFromCondition(or_->op0(), result);
            featureFlagsFromCondition(or_->op1(), result);
        }
    }

    // Helper function to compute the set of feature flags wrapping the given position.
    static std::map<ID, std::set<std::string>> conditionalFeatures(position_t p) {
        std::map<ID, std::set<std::string>> result;

        // We walk up the full path to discover all feature conditionals wrapping this position.
        for ( const auto& parent : p.path ) {
            if ( const auto& if_ = parent.node.tryAs<statement::If>() ) {
                const auto condition = if_->condition();
                if ( ! condition )
                    continue;

                featureFlagsFromCondition(*condition, result);
            }

            else if ( const auto& ternary = parent.node.tryAs<expression::Ternary>() ) {
                featureFlagsFromCondition(ternary->condition(), result);
            }
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
                    const auto feature = *requirement.valueAsString();

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

    void operator()(const declaration::Type& x, position_t p) {
        switch ( _stage ) {
            case Stage::COLLECT:
                // Nothing.
                break;

            case Stage::TRANSFORM: {
                if ( ! _features.count(x.canonicalID()) )
                    break;

                // Add type comment documenting enabled features.
                auto meta = x.meta();
                auto comments = meta.comments();

                if ( auto enabled_features = util::filter(_features.at(x.canonicalID()),
                                                          [](const auto& feature) { return feature.second; });
                     ! enabled_features.empty() ) {
                    comments.push_back(util::fmt("Type %s supports the following features:", x.id()));
                    for ( const auto& feature : enabled_features )
                        comments.push_back(util::fmt("    - %s", feature.first));
                }

                meta.setComments(std::move(comments));
                p.node.as<declaration::Type>().setMeta(std::move(meta));
                break;
            }
        }
    }
};

struct MemberVisitor : OptimizerVisitor, visitor::PreOrder<bool, MemberVisitor> {
    // Map tracking whether a member is used in the code.
    std::map<std::string, bool> _used;

    // Map tracking for each type which features are enabled.
    std::map<ID, std::map<std::string, bool>> _features;

    void collect(Node& node) override {
        _stage = Stage::COLLECT;

        for ( auto i : this->walk(&node) )
            dispatch(i);

        if ( logger().isEnabled(logging::debug::OptimizerCollect) ) {
            HILTI_DEBUG(logging::debug::OptimizerCollect, "members:");

            HILTI_DEBUG(logging::debug::OptimizerCollect, "    feature status:");
            for ( const auto& [id, features] : _features ) {
                std::stringstream ss;
                ss << "        " << id << ':';
                for ( const auto& [feature, enabled] : features )
                    ss << util::fmt(" %s=%d", feature, enabled);
                HILTI_DEBUG(logging::debug::OptimizerCollect, ss.str());
            }

            for ( const auto& [id, used] : _used )
                HILTI_DEBUG(logging::debug::OptimizerCollect, util::fmt("    %s used=%d", id, used));
        }
    }

    bool prune_decls(Node& node) override {
        _stage = Stage::PRUNE_DECLS;

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

    result_t operator()(const Module& m, position_t p) {
        _current_module = &p.node.as<Module>();
        return false;
    }

    result_t operator()(const declaration::Field& x, position_t p) {
        auto type_id = p.parent().as<Type>().typeID();
        if ( ! type_id )
            return false;

        // We never remove member marked `&always-emit`.
        if ( AttributeSet::find(x.attributes(), "&always-emit") )
            return false;

        // We only remove member marked `&internal`.
        if ( ! AttributeSet::find(x.attributes(), "&internal") )
            return false;

        auto member_id = util::join({*type_id, x.id()}, "::");

        switch ( _stage ) {
            case Stage::COLLECT: {
                // Record the member if it is not yet known.
                _used.insert({member_id, false});
                break;
            }

            case Stage::PRUNE_DECLS: {
                if ( ! _used.at(member_id) ) {
                    // Check whether the field depends on an active feature in which case we do not remove the
                    // field.
                    if ( _features.count(*type_id) ) {
                        const auto& features = _features.at(*type_id);

                        auto dependent_features =
                            hilti::node::transform(AttributeSet::findAll(x.attributes(), "&needed-by-feature"),
                                                   [](const Attribute& attr) { return *attr.valueAsString(); });

                        for ( const auto& dependent_feature_ :
                              AttributeSet::findAll(x.attributes(), "&needed-by-feature") ) {
                            auto dependent_feature = *dependent_feature_.valueAsString();

                            // The feature flag is known and the feature is active.
                            if ( features.count(dependent_feature) && features.at(dependent_feature) )
                                return false; // Use `return` instead of `break` here to break out of `switch`.
                        }
                    }

                    HILTI_DEBUG(logging::debug::Optimizer, util::fmt("removing unused member '%s'", member_id));

                    removeNode(p);

                    return true;
                }
            }
            case Stage::PRUNE_USES:
                // Nothing.
                break;
        }

        return false;
    }

    result_t operator()(const expression::Member& x, position_t p) {
        switch ( _stage ) {
            case Stage::COLLECT: {
                auto expr = p.parent().children()[1].tryAs<Expression>();
                if ( ! expr )
                    break;

                const auto type = innermostType(expr->type());

                auto struct_ = type.tryAs<type::Struct>();
                if ( ! struct_ )
                    break;

                auto type_id = type.typeID();
                if ( ! type_id )
                    break;

                auto member_id = util::join({*type_id, x.id()}, "::");

                // Record the member as used.
                _used[member_id] = true;
                break;
            }
            case Stage::PRUNE_USES:
            case Stage::PRUNE_DECLS: break;
        }

        return false;
    }

    result_t operator()(const expression::ResolvedID& x, position_t p) {
        switch ( _stage ) {
            case Stage::COLLECT: {
                if ( ! x.declaration().isA<declaration::Field>() )
                    return false;

                // Record the member as used.
                _used[x.id()] = true;
                break;
            }
            case Stage::PRUNE_USES:
            case Stage::PRUNE_DECLS:
                // Nothing.
                break;
        }

        return false;
    }

    result_t operator()(const declaration::Constant& x, position_t p) {
        switch ( _stage ) {
            case Stage::COLLECT: {
                // Check whether the feature flag matches the type of the field.
                if ( ! util::startsWith(x.id(), "__feat%") )
                    break;

                auto tokens = util::split(x.id(), "%");
                assert(tokens.size() == 3);

                auto type_id = ID(util::replace(tokens[1], "__", "::"));
                auto feature = tokens[2];
                auto is_active = x.value().as<expression::Ctor>().ctor().as<ctor::Bool>().value();

                _features[std::move(type_id)][std::move(feature)] = is_active;

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

void Optimizer::run() {
    util::timing::Collector _("hilti/compiler/optimizer");

    // Create a full list of units to run on. This includes both the units
    // explicitly passed on construction as well as their dependencies.
    auto units = [&]() {
        // We initially store the list as a `set` to ensure uniqueness, but
        // convert to a `vector` so we can mutate entries while iterating.
        auto UnitCmp = [](const std::shared_ptr<Unit>& lhs, const std::shared_ptr<Unit>& rhs) {
            return lhs->uniqueID() < rhs->uniqueID();
        };
        std::set<std::shared_ptr<Unit>, decltype(UnitCmp)> units(UnitCmp);

        for ( auto& unit : _units ) {
            units.insert(unit);

            for ( const auto& dep : unit->dependencies() )
                units.insert(dep.lock());
        }

        return std::vector<std::shared_ptr<Unit>>{units.begin(), units.end()};
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
            v.collect(unit->module());

        for ( auto& unit : units )
            v.transform(unit->module());
    }

    const std::map<std::string, std::function<std::unique_ptr<OptimizerVisitor>()>> creators =
        {{"constant_folding", []() { return std::make_unique<ConstantFoldingVisitor>(); }},
         {"functions", []() { return std::make_unique<FunctionVisitor>(); }},
         {"members", []() { return std::make_unique<MemberVisitor>(); }},
         {"types", []() { return std::make_unique<TypeVisitor>(); }}};

    // If no user-specified passes are given enable all of them.
    if ( ! passes ) {
        passes = std::set<std::string>();
        for ( const auto& [pass, _] : creators )
            passes->insert(pass);
    }

    size_t round = 0;
    while ( true ) {
        bool modified = false;

        // NOTE: We do not use `util::transform` here to guarantee a consistent order of the visitors.
        std::vector<std::unique_ptr<OptimizerVisitor>> vs;
        vs.reserve(passes->size());
        for ( const auto& pass : *passes )
            if ( creators.count(pass) )
                vs.push_back(creators.at(pass)());

        for ( auto& v : vs ) {
            for ( auto& unit : units ) {
                HILTI_DEBUG(logging::debug::OptimizerCollect,
                            util::fmt("processing %s round=%d", unit->module().location().file(), round));
                v->collect(unit->module());
            }

            for ( auto& unit : units )
                modified = v->prune_uses(unit->module()) || modified;

            for ( auto& unit : units )
                modified = v->prune_decls(unit->module()) || modified;
        };

        if ( ! modified )
            break;

        ++round;
    }

    // Clear cached information which might become outdated due to edits.
    for ( auto& unit : units ) {
        auto v = hilti::visitor::PreOrder<>();
        for ( auto i : v.walk(&unit->module()) ) {
            i.node.clearScope();
        }
    }
}

} // namespace hilti
