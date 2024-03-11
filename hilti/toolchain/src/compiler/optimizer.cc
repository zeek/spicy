// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include "hilti/compiler/detail/optimizer.h"

#include <algorithm>
#include <optional>
#include <string>
#include <tuple>
#include <utility>

#include <hilti/rt/util.h>

#include <hilti/ast/builder/builder.h>
#include <hilti/ast/ctors/default.h>
#include <hilti/ast/declaration.h>
#include <hilti/ast/declarations/constant.h>
#include <hilti/ast/declarations/function.h>
#include <hilti/ast/declarations/imported-module.h>
#include <hilti/ast/expressions/ctor.h>
#include <hilti/ast/expressions/logical-and.h>
#include <hilti/ast/expressions/logical-not.h>
#include <hilti/ast/expressions/logical-or.h>
#include <hilti/ast/expressions/member.h>
#include <hilti/ast/expressions/name.h>
#include <hilti/ast/expressions/ternary.h>
#include <hilti/ast/node.h>
#include <hilti/ast/scope-lookup.h>
#include <hilti/ast/statements/block.h>
#include <hilti/ast/statements/while.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/bool.h>
#include <hilti/ast/types/enum.h>
#include <hilti/ast/types/reference.h>
#include <hilti/ast/types/struct.h>
#include <hilti/ast/visitor.h>
#include <hilti/base/logger.h>
#include <hilti/base/timing.h>
#include <hilti/base/util.h>

namespace hilti {

namespace logging::debug {
inline const DebugStream Optimizer("optimizer");
inline const DebugStream OptimizerCollect("optimizer-collect");
} // namespace logging::debug

// Helper function to extract innermost type, removing any wrapping in reference or container types.
QualifiedType* innermostType(QualifiedType* type) {
    if ( type->type()->isReferenceType() )
        return innermostType(type->type()->dereferencedType());

    if ( type->type()->iteratorType() )
        return innermostType(type->type()->elementType());

    return type;
}

bool isFeatureFlag(const ID& id) { return util::startsWith(id.local(), "__feat%"); }

// Helper to extract `(ID, feature)` from a feature constant.
auto idFeatureFromConstant(const ID& featureConstant) -> std::optional<std::pair<ID, std::string>> {
    const auto& id = featureConstant.local();

    if ( ! isFeatureFlag(id) )
        return {};

    const auto& tokens = util::split(id, "%");
    assert(tokens.size() == 3);

    auto type_id = ID(util::replace(tokens[1], "@@", "::"));
    const auto& feature = tokens[2];

    return {{type_id, feature}};
};


class OptimizerVisitor : public visitor::MutatingPreOrder {
public:
    using visitor::MutatingPreOrder::MutatingPreOrder;

    enum class Stage { COLLECT, PRUNE_USES, PRUNE_DECLS };
    Stage _stage = Stage::COLLECT;
    declaration::Module* _current_module = nullptr;

    void removeNode(Node* old, const std::string& msg = "") { replaceNode(old, nullptr, msg); }

    ~OptimizerVisitor() override = default;
    virtual void collect(Node*) {}
    virtual bool prune_uses(Node*) { return false; }
    virtual bool prune_decls(Node*) { return false; }

    void operator()(declaration::Module* n) final { _current_module = n; }
};

struct FunctionVisitor : OptimizerVisitor {
    using OptimizerVisitor::OptimizerVisitor;

    struct Uses {
        bool hook = false;
        bool defined = false;
        bool referenced = false;
    };

    bool _collect_again = false;

    // Lookup table for feature name -> required.
    using Features = std::map<std::string, bool>;

    // Lookup table for typename -> features.
    std::map<ID, Features> _features;

    std::map<ID, Uses> _data;

    void collect(Node* node) override {
        _stage = Stage::COLLECT;

        while ( true ) {
            _collect_again = false;
            visitor::visit(*this, node);

            if ( logger().isEnabled(logging::debug::OptimizerCollect) ) {
                HILTI_DEBUG(logging::debug::OptimizerCollect, "functions:");
                for ( const auto& [id, uses] : _data )
                    HILTI_DEBUG(logging::debug::OptimizerCollect,
                                util::fmt("    %s: defined=%d referenced=%d hook=%d", id, uses.defined, uses.referenced,
                                          uses.hook));
            }

            if ( ! _collect_again )
                break;
        }
    }

    bool prune(Node* node) {
        switch ( _stage ) {
            case Stage::PRUNE_DECLS:
            case Stage::PRUNE_USES: break;
            case Stage::COLLECT: util::cannotBeReached();
        }

        bool any_modification = false;

        while ( true ) {
            clearModified();
            visitor::visit(*this, node);

            if ( ! isModified() )
                break;

            any_modification = true;
        }

        return any_modification;
    }

    bool prune_uses(Node* node) override {
        _stage = Stage::PRUNE_USES;
        return prune(node);
    }

    bool prune_decls(Node* node) override {
        _stage = Stage::PRUNE_DECLS;
        return prune(node);
    }

    void operator()(declaration::Field* n) final {
        if ( ! n->type()->type()->isA<type::Function>() )
            return;

        if ( ! n->parent()->isA<type::Struct>() )
            return;

        const auto& function_id = n->fullyQualifiedID();
        assert(function_id);

        switch ( _stage ) {
            case Stage::COLLECT: {
                auto& function = _data[function_id];

                auto fn = n->childrenOfType<Function>();
                assert(fn.size() <= 1);

                // If the member declaration is marked `&always-emit` mark it as implemented.
                if ( n->attributes()->has("&always-emit") )
                    function.defined = true;

                // If the member declaration includes a body mark it as implemented.
                if ( ! fn.empty() && (*fn.begin())->body() )
                    function.defined = true;

                // If the unit is wrapped in a type with a `&cxxname`
                // attribute its members are defined in C++ as well.
                auto type_ = n->parent<declaration::Type>();

                if ( type_ && type_->attributes()->has("&cxxname") )
                    function.defined = true;

                if ( n->type()->type()->as<type::Function>()->flavor() == type::function::Flavor::Hook )
                    function.hook = true;

                if ( auto type = type_ ) {
                    for ( const auto& requirement : n->attributes()->findAll("&needed-by-feature") ) {
                        auto feature = *requirement->valueAsString();

                        // If no feature constants were collected yet, reschedule us for the next collection pass.
                        //
                        // NOTE: If we emit a `&needed-by-feature` attribute we also always emit a matching feature
                        // constant, so eventually at this point we will see at least one feature constant.
                        if ( _features.empty() ) {
                            _collect_again = true;
                            return;
                        }

                        auto it = _features.find(type->type()->type()->typeID());
                        if ( it == _features.end() )
                            // No feature requirements known for type.
                            continue;

                        function.referenced = function.referenced || it->second.at(feature);
                    }
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
                    removeNode(n);
                    return;
                }

                break;
            }
        }
    }

    void operator()(declaration::Function* n) final {
        ID function_id;
        if ( auto prototype = context()->lookup(n->linkedPrototypeIndex()) )
            function_id = prototype->fullyQualifiedID();
        else
            function_id = n->fullyQualifiedID();

        switch ( _stage ) {
            case Stage::COLLECT: {
                // Record this function if it is not already known.
                auto& function = _data[function_id];

                const auto& fn = n->function();

                // If the declaration contains a function with a body mark the function as defined.
                if ( fn->body() )
                    function.defined = true;

                // If the declaration has a `&cxxname` it is defined in C++.
                else if ( fn->attributes()->has("&cxxname") )
                    function.defined = true;

                // If the member declaration is marked `&always-emit` mark it as referenced.
                if ( fn->attributes()->has("&always-emit") )
                    function.referenced = true;

                // If the function is public mark is as referenced.
                if ( n->linkage() == declaration::Linkage::Public )
                    function.referenced = true;

                // For implementation of methods check whether the method
                // should only be emitted when certain features are active.
                if ( auto decl = context()->lookup(n->linkedDeclarationIndex()) ) {
                    for ( const auto& requirement : fn->attributes()->findAll("&needed-by-feature") ) {
                        auto feature = *requirement->valueAsString();

                        // If no feature constants were collected yet, reschedule us for the next collection pass.
                        //
                        // NOTE: If we emit a `&needed-by-feature` attribute we also always emit a matching feature
                        // constant, so eventually at this point we will see at least one feature constant.
                        if ( _features.empty() ) {
                            _collect_again = true;
                            return;
                        }

                        auto it = _features.find(decl->fullyQualifiedID());
                        if ( it == _features.end() )
                            // No feature requirements known for type.
                            continue;

                        // Mark the function as referenced if it is needed by an active feature.
                        function.referenced = function.referenced || it->second.at(feature);
                    }
                }

                if ( fn->ftype()->flavor() == type::function::Flavor::Hook )
                    function.hook = true;

                const auto decl = context()->lookup(n->linkedDeclarationIndex());

                switch ( fn->callingConvention() ) {
                    case function::CallingConvention::ExternNoSuspend:
                    case function::CallingConvention::Extern: {
                        // If the declaration is `extern` and the unit is `public`, the function
                        // is part of an externally visible API and potentially used elsewhere.

                        if ( decl )
                            function.referenced =
                                function.referenced || decl->linkage() == declaration::Linkage::Public;
                        else
                            function.referenced = true;

                        break;
                    }
                    case function::CallingConvention::Standard:
                        // Nothing.
                        break;
                }

                switch ( n->linkage() ) {
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
                        if ( ! decl ) {
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
                    removeNode(n, "removing declaration for unused hook function");
                    return;
                }

                if ( ! function.hook && ! function.referenced ) {
                    removeNode(n, "removing declaration for unused function");
                    return;
                }

                break;
        }
    }

    void operator()(operator_::struct_::MemberCall* n) final {
        if ( ! n->hasOp1() )
            return;

        assert(n->hasOp0());

        auto type = n->op0()->type();

        auto struct_ = type->type()->tryAs<type::Struct>();
        if ( ! struct_ )
            return;

        const auto& member = n->op1()->tryAs<expression::Member>();
        if ( ! member )
            return;

        auto field = struct_->field(member->id());
        if ( ! field )
            return;

        const auto& function_id = field->fullyQualifiedID();

        if ( ! function_id )
            return;

        switch ( _stage ) {
            case Stage::COLLECT: {
                auto& function = _data[function_id];

                function.referenced = true;

                return;
            }

            case Stage::PRUNE_USES: {
                const auto& function = _data.at(function_id);

                // Replace call node referencing unimplemented member function with default value.
                if ( ! function.defined ) {
                    if ( n->op0()->type()->type()->isA<type::Struct>() )
                        replaceNode(n, builder()->expressionCtor(builder()->ctorDefault(n->result()->type())),
                                    "replacing call to unimplemented method with default value");
                    return;
                }

                break;
            }

            case Stage::PRUNE_DECLS:
                // Nothing.
                break;
        }
    }

    void operator()(operator_::function::Call* n) final {
        if ( ! n->hasOp0() )
            return;

        auto decl = n->op0()->as<expression::Name>()->resolvedDeclaration();
        auto function_id = decl->fullyQualifiedID();
        assert(function_id);

        switch ( _stage ) {
            case Stage::COLLECT: {
                auto& function = _data[function_id];

                function.referenced = true;
                return;
            }

            case Stage::PRUNE_USES: {
                const auto& function = _data.at(function_id);

                // Replace call node referencing unimplemented hook with default value.
                if ( function.hook && ! function.defined ) {
                    if ( auto fn = decl->tryAs<declaration::Function>() ) {
                        replaceNode(n,
                                    builder()->expressionCtor(
                                        builder()->ctorDefault(fn->function()->ftype()->result()->type())),
                                    "replacing call to unimplemented function with default value");
                        return;
                    }
                }

                break;
            }

            case Stage::PRUNE_DECLS:
                // Nothing.
                break;
        }
    }

    void operator()(declaration::Constant* n) final {
        switch ( _stage ) {
            case Stage::COLLECT: {
                std::optional<bool> value;
                if ( auto ctor = n->value()->tryAs<expression::Ctor>() )
                    if ( auto bool_ = ctor->ctor()->tryAs<ctor::Bool>() )
                        value = bool_->value();

                if ( ! value )
                    break;

                const auto& id = n->id();

                const auto& id_feature = idFeatureFromConstant(n->id());
                if ( ! id_feature )
                    break;

                const auto& [type_id, feature] = *id_feature;

                // We only work on feature flags.
                if ( ! isFeatureFlag(id) )
                    break;

                _features[type_id].insert({feature, *value});
                break;
            }

            case Stage::PRUNE_USES:
            case Stage::PRUNE_DECLS: break;
        }
    }
};

struct TypeVisitor : OptimizerVisitor {
    using OptimizerVisitor::OptimizerVisitor;

    std::map<ID, bool> _used;

    void collect(Node* node) override {
        _stage = Stage::COLLECT;

        visitor::visit(*this, node);

        if ( logger().isEnabled(logging::debug::OptimizerCollect) ) {
            HILTI_DEBUG(logging::debug::OptimizerCollect, "types:");
            for ( const auto& [id, used] : _used )
                HILTI_DEBUG(logging::debug::OptimizerCollect, util::fmt("    %s: used=%d", id, used));
        }
    }

    bool prune_decls(Node* node) override {
        _stage = Stage::PRUNE_DECLS;

        clearModified();
        visitor::visit(*this, node);

        return isModified();
    }

    // XXX

    void operator()(declaration::Field* n) final {
        switch ( _stage ) {
            case Stage::COLLECT: {
                const auto type_id = n->type()->type()->typeID();

                if ( ! type_id )
                    break;

                // Record this type as used.
                _used[type_id] = true;

                break;
            }
            case Stage::PRUNE_USES:
            case Stage::PRUNE_DECLS:
                // Nothing.
                break;
        }
    }

    void operator()(declaration::Type* n) final {
        // We currently only handle type declarations for struct types or enum types.
        //
        // TODO(bbannier): Handle type aliases.
        if ( const auto& type = n->type(); ! (type->type()->isA<type::Struct>() || type->type()->isA<type::Enum>()) )
            return;

        const auto type_id = n->typeID();

        if ( ! type_id )
            return;

        switch ( _stage ) {
            case Stage::COLLECT:
                // Record the type if not already known. If the type is part of an external API record it as used.
                _used.insert({type_id, n->linkage() == declaration::Linkage::Public});
                break;

            case Stage::PRUNE_USES: break;
            case Stage::PRUNE_DECLS:
                if ( ! _used.at(type_id) ) {
                    removeNode(n, "removing unused type");
                    return;
                }

                break;
        }
    }

    void operator()(UnqualifiedType* n) final {
        if ( n->parent(2)->isA<declaration::Type>() )
            return;

        switch ( _stage ) {
            case Stage::COLLECT: {
                if ( const auto& type_id = n->typeID() )
                    // Record this type as used.
                    _used[type_id] = true;

                break;
            }

            case Stage::PRUNE_USES:
            case Stage::PRUNE_DECLS:
                // Nothing.
                break;
        }
    }

    void operator()(expression::Name* n) final {
        switch ( _stage ) {
            case Stage::COLLECT: {
                const auto type = innermostType(n->type());

                const auto& type_id = type->type()->typeID();

                if ( ! type_id )
                    break;

                // Record this type as used.
                _used[type_id] = true;

                break;
            }
            case Stage::PRUNE_USES:
            case Stage::PRUNE_DECLS:
                // Nothing.
                break;
        }
    }

    void operator()(declaration::Function* n) final {
        switch ( _stage ) {
            case Stage::COLLECT: {
                if ( const auto decl = context()->lookup(n->linkedDeclarationIndex()) ) {
                    // If this type is referenced by a function declaration it is used.
                    _used[decl->fullyQualifiedID()] = true;
                    break;
                }
            }

            case Stage::PRUNE_USES:
            case Stage::PRUNE_DECLS:
                // Nothing.
                break;
        }
    }

    void operator()(expression::Type_* n) final {
        switch ( _stage ) {
            case Stage::COLLECT: {
                const auto type_id = n->typeValue()->type()->typeID();
                ;

                if ( ! type_id )
                    break;

                // Record this type as used.
                _used[type_id] = true;
                break;
            }

            case Stage::PRUNE_USES:
            case Stage::PRUNE_DECLS:
                // Nothing.
                break;
        }
    }
};

struct ConstantFoldingVisitor : OptimizerVisitor {
    using OptimizerVisitor::OptimizerVisitor;

    std::map<ID, bool> _constants;

    void collect(Node* node) override {
        _stage = Stage::COLLECT;

        visitor::visit(*this, node);

        if ( logger().isEnabled(logging::debug::OptimizerCollect) ) {
            HILTI_DEBUG(logging::debug::OptimizerCollect, "constants:");
            std::vector<std::string> xs;
            for ( const auto& [id, value] : _constants )
                HILTI_DEBUG(logging::debug::OptimizerCollect, util::fmt("    %s: value=%d", id, value));
        }
    }

    bool prune_uses(Node* node) override {
        _stage = Stage::PRUNE_USES;

        bool any_modification = false;

        while ( true ) {
            clearModified();
            visitor::visit(*this, node);

            if ( ! isModified() )
                break;

            any_modification = true;
        }

        return any_modification;
    }

    // XXX

    void operator()(declaration::Constant* n) final {
        if ( ! n->type()->type()->isA<type::Bool>() )
            return;

        const auto& id = n->fullyQualifiedID();
        assert(id);

        switch ( _stage ) {
            case Stage::COLLECT: {
                if ( auto ctor = n->value()->tryAs<expression::Ctor>() )
                    if ( auto bool_ = ctor->ctor()->tryAs<ctor::Bool>() )
                        _constants[id] = bool_->value();

                break;
            }

            case Stage::PRUNE_USES:
            case Stage::PRUNE_DECLS: break;
        }
    }

    void operator()(expression::Name* n) final {
        switch ( _stage ) {
            case Stage::COLLECT:
            case Stage::PRUNE_DECLS: return;
            case Stage::PRUNE_USES: {
                auto decl = n->resolvedDeclaration();
                auto id = decl->fullyQualifiedID();
                assert(id);

                if ( const auto& constant = _constants.find(id); constant != _constants.end() ) {
                    if ( n->type()->type()->isA<type::Bool>() ) {
                        replaceNode(n, builder()->bool_((constant->second)), "inlining constant");
                        return;
                    }
                }
            }
        }
    }

    std::optional<bool> tryAsBoolLiteral(Expression* x) {
        if ( auto expression = x->tryAs<expression::Ctor>() )
            if ( auto bool_ = expression->ctor()->tryAs<ctor::Bool>() )
                return {bool_->value()};

        return {};
    }

    void operator()(statement::If* n) final {
        switch ( _stage ) {
            case Stage::COLLECT:
            case Stage::PRUNE_DECLS: return;
            case Stage::PRUNE_USES: {
                if ( auto bool_ = tryAsBoolLiteral(n->condition()) ) {
                    if ( auto else_ = n->false_() ) {
                        if ( ! bool_.value() ) {
                            replaceNode(n, else_);
                            return;
                        }
                        else {
                            replaceNode(n, builder()->statementIf(n->init(), n->condition(), n->true_(), nullptr));
                            return;
                        }
                    }
                    else {
                        if ( ! bool_.value() ) {
                            removeNode(n);
                            return;
                        }
                        else {
                            replaceNode(n, n->true_());
                            return;
                        }
                    }

                    return;
                };
            }
        }
    }

    void operator()(expression::Ternary* n) final {
        switch ( _stage ) {
            case OptimizerVisitor::Stage::COLLECT:
            case OptimizerVisitor::Stage::PRUNE_DECLS: return;
            case OptimizerVisitor::Stage::PRUNE_USES: {
                if ( auto bool_ = tryAsBoolLiteral(n->condition()) ) {
                    if ( *bool_ )
                        replaceNode(n, n->true_());
                    else
                        replaceNode(n, n->false_());

                    return;
                }
            }
        }
    }

    void operator()(expression::LogicalOr* n) final {
        switch ( _stage ) {
            case Stage::COLLECT:
            case Stage::PRUNE_DECLS: break;
            case Stage::PRUNE_USES: {
                auto lhs = tryAsBoolLiteral(n->op0());
                auto rhs = tryAsBoolLiteral(n->op1());

                if ( lhs && rhs ) {
                    replaceNode(n, builder()->bool_(lhs.value() || rhs.value()));
                    return;
                }
            }
        };
    }

    void operator()(expression::LogicalAnd* n) final {
        switch ( _stage ) {
            case Stage::COLLECT:
            case Stage::PRUNE_DECLS: break;
            case Stage::PRUNE_USES: {
                auto lhs = tryAsBoolLiteral(n->op0());
                auto rhs = tryAsBoolLiteral(n->op1());

                if ( lhs && rhs ) {
                    replaceNode(n, builder()->bool_(lhs.value() && rhs.value()));
                    return;
                }
            }
        };
    }

    void operator()(expression::LogicalNot* n) final {
        switch ( _stage ) {
            case Stage::COLLECT:
            case Stage::PRUNE_DECLS: break;
            case Stage::PRUNE_USES: {
                if ( auto op = tryAsBoolLiteral(n->expression()) ) {
                    replaceNode(n, builder()->bool_(! op.value()));
                    return;
                }
            }
        };
    }

    void operator()(statement::While* x) final {
        switch ( _stage ) {
            case Stage::COLLECT:
            case Stage::PRUNE_DECLS: return;
            case Stage::PRUNE_USES: {
                const auto& cond = x->condition();
                if ( ! cond )
                    return;

                const auto val = tryAsBoolLiteral(cond);
                if ( ! val )
                    return;

                // If the `while` condition is true we never run the `else` block.
                if ( *val && x->else_() ) {
                    recordChange(x, "removing else block of while loop with true condition");
                    x->removeElse(context());
                    return;
                }

                // If the `while` condition is false we never enter the loop, and
                // run either the `else` block if it is present or nothing.
                else if ( ! *val ) {
                    if ( x->else_() )
                        replaceNode(x, x->else_(), "replacing while loop with its else block");
                    else {
                        recordChange(x, "removing while loop with false condition");
                        x->parent()->removeChild(x->as<Node>());
                    }

                    return;
                }

                return;
            }
        }
    }
};

// This visitor collects requirement attributes in the AST and toggles unused features.
class FeatureRequirementsVisitor : public visitor::MutatingPreOrder {
public:
    using visitor::MutatingPreOrder::MutatingPreOrder;

    // Lookup table for feature name -> required.
    using Features = std::map<std::string, bool>;

    // Lookup table for typename -> features.
    std::map<ID, Features> _features;

    enum class Stage { COLLECT, TRANSFORM };
    Stage _stage = Stage::COLLECT;

    void collect(Node* node) {
        _stage = Stage::COLLECT;

        visitor::visit(*this, node);

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

    void transform(Node* node) {
        _stage = Stage::TRANSFORM;
        visitor::visit(*this, node);
    }

    void operator()(declaration::Constant* n) final {
        const auto& id = n->id();

        // We only work on feature flags.
        if ( ! isFeatureFlag(id) )
            return;

        const auto& id_feature = idFeatureFromConstant(n->id());
        if ( ! id_feature )
            return;

        const auto& [type_id, feature] = *id_feature;

        switch ( _stage ) {
            case Stage::COLLECT: {
                // Record the feature as unused for the type if it was not already recorded.
                _features[type_id].insert({feature, false});
                break;
            }

            case Stage::TRANSFORM: {
                const auto required = _features.at(type_id).at(feature);
                const auto value = n->value()->as<expression::Ctor>()->ctor()->as<ctor::Bool>()->value();

                if ( required != value ) {
                    n->setValue(builder()->context(), builder()->bool_(false));
                    recordChange(n, util::fmt("disabled feature '%s' of type '%s' since it is not used", feature,
                                              type_id));
                }

                break;
            }
        }
    }

    void operator()(operator_::function::Call* n) final {
        switch ( _stage ) {
            case Stage::COLLECT: {
                // Collect parameter requirements from the declaration of the called function.
                std::vector<std::set<std::string>> requirements;

                auto rid = n->op0()->tryAs<expression::Name>();
                if ( ! rid )
                    return;

                auto decl = rid->resolvedDeclaration();
                const auto& fn = decl->tryAs<declaration::Function>();
                if ( ! fn )
                    return;

                for ( const auto& parameter : fn->function()->ftype()->parameters() ) {
                    // The requirements of this parameter.
                    std::set<std::string> reqs;

                    for ( const auto& requirement : parameter->attributes()->findAll("&requires-type-feature") ) {
                        auto feature = *requirement->valueAsString();
                        reqs.insert(std::move(feature));
                    }

                    requirements.push_back(std::move(reqs));
                }

                const auto ignored_features = conditionalFeatures(n);

                // Collect the types of parameters from the actual arguments.
                // We cannot get this information from the declaration since it
                // might use `any` types. Correlate this with the requirement
                // information collected previously and update the global list
                // of feature requirements.
                std::size_t i = 0;
                for ( const auto& arg : n->op1()->as<expression::Ctor>()->ctor()->as<ctor::Tuple>()->value() ) {
                    // Instead of applying the type requirement only to the
                    // potentially unref'd passed value's type, we also apply
                    // it to the element type of list args. Since this
                    // optimizer pass removes code worst case this could lead
                    // to us optimizing less.
                    auto type = innermostType(arg->type());

                    // Ignore arguments types without type ID (e.g., builtin types).
                    const auto& type_id = type->type()->typeID();
                    if ( ! type_id ) {
                        ++i;
                        continue;
                    }

                    for ( const auto& requirement : requirements[i] ) {
                        if ( ! ignored_features.count(type_id) || ! ignored_features.at(type_id).count(requirement) )
                            // Enable the required feature.
                            _features[type_id][requirement] = true;
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

    void operator()(operator_::struct_::MemberCall* n) final {
        switch ( _stage ) {
            case Stage::COLLECT: {
                auto type = n->op0()->type();
                while ( type->type()->isReferenceType() )
                    type = type->type()->dereferencedType();

                const auto struct_ = type->type()->tryAs<type::Struct>();
                if ( ! struct_ )
                    break;

                const auto& member = n->op1()->as<expression::Member>();

                const auto field = struct_->field(member->id());
                if ( ! field )
                    break;

                const auto ignored_features = conditionalFeatures(n);

                // Check if access to the field has type requirements.
                if ( auto type_id = type->type()->typeID() )
                    for ( const auto& requirement : field->attributes()->findAll("&needed-by-feature") ) {
                        const auto feature = *requirement->valueAsString();
                        if ( ! ignored_features.count(type_id) || ! ignored_features.at(type_id).count(feature) )
                            // Enable the required feature.
                            _features[type_id][*requirement->valueAsString()] = true;
                    }

                // Check if call imposes requirements on any of the types of the arguments.
                const auto& op = static_cast<const struct_::MemberCall&>(n->operator_());
                assert(op.declaration());
                auto ftype = op.declaration()->type()->type()->as<type::Function>();

                const auto parameters = ftype->parameters();
                if ( parameters.empty() )
                    break;

                const auto& args = n->op2()->as<expression::Ctor>()->ctor()->as<ctor::Tuple>()->value();

                for ( size_t i = 0; i < parameters.size(); ++i ) {
                    // Since the declaration might use `any` types, get the
                    // type of the parameter from the passed argument.

                    // Instead of applying the type requirement only to the
                    // potentially unref'd passed value's type, we also apply
                    // it to the element type of list args. Since this
                    // optimizer pass removes code worst case this could lead
                    // to us optimizing less.
                    const auto type = innermostType(args[i]->type());
                    const auto& param = parameters[i];

                    if ( auto type_id = type->type()->typeID() )
                        for ( const auto& requirement : param->attributes()->findAll("&requires-type-feature") ) {
                            const auto feature = *requirement->valueAsString();
                            if ( ! ignored_features.count(type_id) || ! ignored_features.at(type_id).count(feature) ) {
                                // Enable the required feature.
                                _features[type_id][feature] = true;
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
    static void featureFlagsFromCondition(Expression* condition, std::map<ID, std::set<std::string>>& result) {
        // Helper to extract `(ID, feature)` from a feature constant.
        auto idFeatureFromConstant = [](const ID& featureConstant) -> std::optional<std::pair<ID, std::string>> {
            // Split away the module part of the resolved ID.
            auto id = util::split1(featureConstant, "::").second;

            if ( ! util::startsWith(id, "__feat") )
                return {};

            const auto& tokens = util::split(id, "%");
            assert(tokens.size() == 3);

            auto type_id = ID(util::replace(tokens[1], "@@", "::"));
            const auto& feature = tokens[2];

            return {{type_id, feature}};
        };

        if ( auto rid = condition->tryAs<expression::Name>() ) {
            if ( auto id_feature = idFeatureFromConstant(rid->id()) )
                result[std::move(id_feature->first)].insert(std::move(id_feature->second));
        }

        // If we did not find a feature constant in the conditional, we
        // could also be dealing with a `OR` of feature constants.
        else if ( auto or_ = condition->tryAs<expression::LogicalOr>() ) {
            featureFlagsFromCondition(or_->op0(), result);
            featureFlagsFromCondition(or_->op1(), result);
        }
    }

    // Helper function to compute the set of feature flags wrapping the given position.
    static std::map<ID, std::set<std::string>> conditionalFeatures(Node* n) {
        std::map<ID, std::set<std::string>> result;

        // We walk up the full path to discover all feature conditionals wrapping this position.
        for ( auto parent = n->parent(); parent; parent = parent->parent() ) {
            if ( const auto& if_ = parent->tryAs<statement::If>() ) {
                const auto condition = if_->condition();
                if ( ! condition )
                    continue;

                featureFlagsFromCondition(condition, result);
            }

            else if ( const auto& ternary = parent->tryAs<expression::Ternary>() ) {
                featureFlagsFromCondition(ternary->condition(), result);
            }
        }

        return result;
    }

    void handleMemberAccess(expression::ResolvedOperator* x) {
        switch ( _stage ) {
            case Stage::COLLECT: {
                auto type_ = x->op0()->type();
                while ( type_->type()->isReferenceType() )
                    type_ = type_->type()->dereferencedType();

                auto type_id = type_->type()->typeID();
                if ( ! type_id )
                    return;

                auto member = x->op1()->tryAs<expression::Member>();
                if ( ! member )
                    return;

                auto lookup = scope::lookupID<declaration::Type>(type_id, x, "type");
                if ( ! lookup )
                    return;

                auto type = lookup->first->template as<declaration::Type>();
                auto struct_ = type->type()->type()->template tryAs<type::Struct>();
                if ( ! struct_ )
                    return;

                auto field = struct_->field(member->id());
                if ( ! field )
                    return;

                const auto ignored_features = conditionalFeatures(x);

                for ( const auto& requirement : field->attributes()->findAll("&needed-by-feature") ) {
                    const auto feature = *requirement->valueAsString();

                    // Enable the required feature if it is not ignored here.
                    if ( ! ignored_features.count(type_id) || ! ignored_features.at(type_id).count(feature) )
                        _features[type_id][feature] = true;
                }

                break;
            }
            case Stage::TRANSFORM:
                // Nothing.
                break;
        }
    }

    void operator()(operator_::struct_::MemberConst* n) final { return handleMemberAccess(n); }
    void operator()(operator_::struct_::MemberNonConst* n) final { return handleMemberAccess(n); }

    void operator()(declaration::Type* n) final {
        switch ( _stage ) {
            case Stage::COLLECT:
                // Nothing.
                break;

            case Stage::TRANSFORM: {
                if ( ! _features.count(n->fullyQualifiedID()) )
                    break;

                // Add type comment documenting enabled features.
                auto meta = n->meta();
                auto comments = meta.comments();

                if ( auto enabled_features = util::filter(_features.at(n->fullyQualifiedID()),
                                                          [](const auto& feature) { return feature.second; });
                     ! enabled_features.empty() ) {
                    comments.push_back(util::fmt("Type %s supports the following features:", n->id()));
                    for ( const auto& feature : enabled_features )
                        comments.push_back(util::fmt("    - %s", feature.first));
                }

                meta.setComments(std::move(comments));
                n->setMeta(std::move(meta));
                break;
            }
        }
    }
};

struct MemberVisitor : OptimizerVisitor {
    using OptimizerVisitor::OptimizerVisitor;

    // Map tracking whether a member is used in the code.
    std::map<std::string, bool> _used;

    // Map tracking for each type which features are enabled.
    std::map<ID, std::map<std::string, bool>> _features;

    void collect(Node* node) override {
        _stage = Stage::COLLECT;

        visitor::visit(*this, node);

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

    bool prune_decls(Node* node) override {
        _stage = Stage::PRUNE_DECLS;

        bool any_modification = false;

        while ( true ) {
            clearModified();

            visitor::visit(*this, node);

            if ( ! isModified() )
                break;

            any_modification = true;
        }

        return any_modification;
    }

    // XXXX

    void operator()(declaration::Field* n) final {
        auto type_id = n->parent()->as<UnqualifiedType>()->typeID();
        if ( ! type_id )
            return;

        // We never remove member marked `&always-emit`.
        if ( n->attributes()->has("&always-emit") )
            return;

        // We only remove member marked `&internal`.
        if ( ! n->attributes()->find("&internal") )
            return;

        auto member_id = util::join({type_id, n->id()}, "::");

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
                    if ( _features.count(type_id) ) {
                        const auto& features = _features.at(type_id);

                        auto dependent_features =
                            hilti::node::transform(n->attributes()->findAll("&needed-by-feature"),
                                                   [](const auto& attr) { return *attr->valueAsString(); });

                        for ( const auto& dependent_feature_ : n->attributes()->findAll("&needed-by-feature") ) {
                            auto dependent_feature = *dependent_feature_->valueAsString();

                            // The feature flag is known and the feature is active.
                            if ( features.count(dependent_feature) && features.at(dependent_feature) )
                                return; // Use `return` instead of `break` here to break out of `switch`.
                        }
                    }

                    removeNode(n, "removing unused member");
                    return;
                }
            }
            case Stage::PRUNE_USES:
                // Nothing.
                break;
        }
    }

    void operator()(expression::Member* n) final {
        switch ( _stage ) {
            case Stage::COLLECT: {
                auto expr = n->parent()->children()[1]->tryAs<Expression>();
                if ( ! expr )
                    break;

                const auto type = innermostType(expr->type());

                auto struct_ = type->type()->tryAs<type::Struct>();
                if ( ! struct_ )
                    break;

                auto type_id = type->type()->typeID();
                if ( ! type_id )
                    break;

                auto member_id = util::join({type_id, n->id()}, "::");

                // Record the member as used.
                _used[member_id] = true;
                break;
            }
            case Stage::PRUNE_USES:
            case Stage::PRUNE_DECLS: break;
        }
    }

    void operator()(expression::Name* n) final {
        switch ( _stage ) {
            case Stage::COLLECT: {
                auto decl = n->resolvedDeclaration();
                if ( ! decl->isA<declaration::Field>() )
                    return;

                // Record the member as used.
                _used[n->id()] = true;
                break;
            }
            case Stage::PRUNE_USES:
            case Stage::PRUNE_DECLS:
                // Nothing.
                break;
        }
    }

    void operator()(declaration::Constant* n) final {
        switch ( _stage ) {
            case Stage::COLLECT: {
                // Check whether the feature flag matches the type of the field.
                if ( ! util::startsWith(n->id(), "__feat%") )
                    break;

                auto tokens = util::split(n->id(), "%");
                assert(tokens.size() == 3);

                auto type_id = ID(tokens[1]);
                auto feature = tokens[2];
                auto is_active = n->value()->as<expression::Ctor>()->ctor()->as<ctor::Bool>()->value();

                type_id = ID(util::replace(type_id, "@@", "::"));
                _features[type_id][feature] = is_active;

                break;
            }
            case Stage::PRUNE_USES:
            case Stage::PRUNE_DECLS:
                // Nothing.
                break;
        }
    }
};

void detail::optimizer::optimize(Builder* builder, ASTRoot* root) {
    util::timing::Collector _("hilti/compiler/optimizer");

    const auto passes__ = rt::getenv("HILTI_OPTIMIZER_PASSES");
    const auto passes_ =
        passes__ ? std::optional(util::split(*passes__, ":")) : std::optional<std::vector<std::string>>();
    auto passes = passes_ ? std::optional(std::set<std::string>(passes_->begin(), passes_->end())) :
                            std::optional<std::set<std::string>>();

    if ( ! passes || passes->count("feature_requirements") ) {
        // The `FeatureRequirementsVisitor` enables or disables code
        // paths and needs to be run before all other passes since
        // it needs to see the code before any optimization edits.
        FeatureRequirementsVisitor v(builder, hilti::logging::debug::Optimizer);
        v.collect(root);
        v.transform(root);
    }

    const std::map<std::string, std::function<std::unique_ptr<OptimizerVisitor>()>> creators =
        {{"constant_folding",
          [&builder]() { return std::make_unique<ConstantFoldingVisitor>(builder, hilti::logging::debug::Optimizer); }},
         {"functions",
          [&builder]() { return std::make_unique<FunctionVisitor>(builder, hilti::logging::debug::Optimizer); }},
         {"members",
          [&builder]() { return std::make_unique<MemberVisitor>(builder, hilti::logging::debug::Optimizer); }},
         {"types", [&builder]() { return std::make_unique<TypeVisitor>(builder, hilti::logging::debug::Optimizer); }}};

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
            HILTI_DEBUG(logging::debug::OptimizerCollect, util::fmt("processing AST, round=%d", round));
            v->collect(root);
            modified = v->prune_uses(root) || modified;
            modified = v->prune_decls(root) || modified;
        };

        if ( ! modified )
            break;

        ++round;
    }

    // Clear cached information which might become outdated due to edits.
    auto v = hilti::visitor::PreOrder();
    for ( auto n : hilti::visitor::range(v, root, {}) )
        n->clearScope();
}

} // namespace hilti
