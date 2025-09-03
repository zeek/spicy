// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include "hilti/compiler/detail/optimizer.h"

#include <algorithm>
#include <memory>
#include <numeric>
#include <optional>
#include <string>
#include <tuple>
#include <unordered_set>
#include <utility>

#include <hilti/rt/util.h>

#include <hilti/ast/builder/builder.h>
#include <hilti/ast/ctors/default.h>
#include <hilti/ast/declaration.h>
#include <hilti/ast/declarations/constant.h>
#include <hilti/ast/declarations/function.h>
#include <hilti/ast/declarations/global-variable.h>
#include <hilti/ast/declarations/imported-module.h>
#include <hilti/ast/declarations/local-variable.h>
#include <hilti/ast/declarations/module.h>
#include <hilti/ast/declarations/parameter.h>
#include <hilti/ast/expressions/assign.h>
#include <hilti/ast/expressions/ctor.h>
#include <hilti/ast/expressions/grouping.h>
#include <hilti/ast/expressions/logical-and.h>
#include <hilti/ast/expressions/logical-not.h>
#include <hilti/ast/expressions/logical-or.h>
#include <hilti/ast/expressions/member.h>
#include <hilti/ast/expressions/name.h>
#include <hilti/ast/expressions/ternary.h>
#include <hilti/ast/function.h>
#include <hilti/ast/node.h>
#include <hilti/ast/operators/reference.h>
#include <hilti/ast/scope-lookup.h>
#include <hilti/ast/statement.h>
#include <hilti/ast/statements/block.h>
#include <hilti/ast/statements/declaration.h>
#include <hilti/ast/statements/expression.h>
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
#include <hilti/compiler/detail/cfg.h>

namespace hilti {

namespace logging::debug {
inline const DebugStream CfgInitial("cfg-initial");
inline const DebugStream CfgFinal("cfg-final");

inline const DebugStream Optimizer("optimizer");
inline const DebugStream OptimizerCollect("optimizer-collect");
} // namespace logging::debug

// Helper function to extract innermost type, removing any wrapping in reference or container types.
static QualifiedType* innermostType(QualifiedType* type) {
    if ( type->type()->isReferenceType() )
        return innermostType(type->type()->dereferencedType());

    if ( type->type()->iteratorType() )
        return innermostType(type->type()->elementType());

    return type;
}

static bool isFeatureFlag(const ID& id) { return util::startsWith(id.local(), "__feat%"); }

// Helper to extract `(ID, feature)` from a feature constant.
static auto idFeatureFromConstant(const ID& feature_constant) -> std::optional<std::pair<ID, std::string>> {
    const auto& id = feature_constant.local();

    if ( ! isFeatureFlag(id) )
        return {};

    const auto& tokens = util::split(id, "%");
    assert(tokens.size() == 3);

    auto type_id = ID(util::replace(tokens[1], "@@", "::"));
    const auto& feature = tokens[2];

    return {{type_id, feature}};
};

using OperatorUses = std::map<const Operator*, std::vector<expression::ResolvedOperator*>>;

// Collects uses of resolved operators
struct CollectUsesPass : public hilti::visitor::PreOrder {
    OperatorUses result;

    OperatorUses collect(Node* node) {
        visitor::visit(*this, node);
        return result;
    }

    void operator()(expression::ResolvedOperator* node) override { result[&node->operator_()].push_back(node); }
};

// Helper function to output control flow graphs for statements.
static std::string dataflowDot(const hilti::Statement& stmt) {
    auto cfg = detail::cfg::CFG(&stmt);
    return cfg.dot();
}

// Helper class to print CFGs to a debug stream.
class PrintCfgVisitor : public visitor::PreOrder {
    logging::DebugStream _stream;

public:
    PrintCfgVisitor(logging::DebugStream stream) : _stream(std::move(stream)) {}

    void operator()(declaration::Function* f) override {
        if ( auto* body = f->function()->body() )
            HILTI_DEBUG(_stream, util::fmt("Function '%s'\n%s", f->id(), dataflowDot(*body)));
    }

    void operator()(declaration::Module* m) override {
        if ( auto* body = m->statements() )
            HILTI_DEBUG(_stream, util::fmt("Module '%s'\n%s", m->id(), dataflowDot(*body)));
    }
};

class OptimizerVisitor : public visitor::MutatingPreOrder {
public:
    using visitor::MutatingPreOrder::MutatingPreOrder;

    enum class Stage { Collect, PruneUses, PruneDecls };
    Stage stage = Stage::Collect;
    declaration::Module* current_module = nullptr;

    void removeNode(Node* old, const std::string& msg = "") { replaceNode(old, nullptr, msg); }

    OptimizerVisitor(Builder* builder, const logging::DebugStream& dbg, const OperatorUses* op_uses)
        : visitor::MutatingPreOrder(builder, dbg), _op_uses(op_uses) {}

    ~OptimizerVisitor() override = default;
    virtual void collect(Node*) {}
    virtual bool pruneUses(Node*) { return false; }
    virtual bool pruneDecls(Node*) { return false; }

    void operator()(declaration::Module* n) override { current_module = n; }

    const OperatorUses::mapped_type* uses(const Operator* x) const {
        if ( ! _op_uses->contains(x) )
            return nullptr;

        return &_op_uses->at(x);
    }

private:
    const OperatorUses* _op_uses = nullptr;
};

struct FunctionVisitor : OptimizerVisitor {
    using OptimizerVisitor::OptimizerVisitor;
    using OptimizerVisitor::operator();

    struct Uses {
        bool hook = false;
        bool defined = false;
        bool referenced = false;
    };

    // Lookup table for feature name -> required.
    using Features = std::map<std::string, bool>;

    // Lookup table for typename -> features.
    std::map<ID, Features> features;

    std::map<ID, Uses> data;

    void collect(Node* node) override {
        stage = Stage::Collect;

        // Helper to compute the total number of collected features over all types.
        auto num_features = [&]() {
            return std::accumulate(features.begin(), features.end(), 0U,
                                   [](auto acc, auto&& f) { return acc + f.second.size(); });
        };

        // Whether a function can be elided depends on which features are active. Since we discover features as we visit
        // the AST (which likely contains multiple modules), we need to iterate until we have collected all features.
        while ( true ) {
            const auto num_features_0 = num_features();

            visitor::visit(*this, node);

            if ( logger().isEnabled(logging::debug::OptimizerCollect) ) {
                HILTI_DEBUG(logging::debug::OptimizerCollect, "functions:");
                for ( const auto& [id, uses] : data )
                    HILTI_DEBUG(logging::debug::OptimizerCollect,
                                util::fmt("    %s: defined=%d referenced=%d hook=%d", id, uses.defined, uses.referenced,
                                          uses.hook));
            }

            const auto num_features_1 = num_features();

            // We have seen everything since no new features were found.
            if ( num_features_0 == num_features_1 )
                break;
        }
    }

    bool prune(Node* node) {
        switch ( stage ) {
            case Stage::PruneDecls:
            case Stage::PruneUses: break;
            case Stage::Collect: util::cannotBeReached();
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

    bool pruneUses(Node* node) override {
        stage = Stage::PruneUses;
        return prune(node);
    }

    bool pruneDecls(Node* node) override {
        stage = Stage::PruneDecls;
        return prune(node);
    }

    void operator()(declaration::Field* n) final {
        if ( ! n->type()->type()->isA<type::Function>() )
            return;

        if ( ! n->parent()->isA<type::Struct>() )
            return;

        const auto& function_id = n->fullyQualifiedID();
        assert(function_id);

        switch ( stage ) {
            case Stage::Collect: {
                auto& function = data[function_id];

                auto fn = n->childrenOfType<Function>();
                assert(fn.size() <= 1);

                // If the member declaration is marked `&always-emit` mark it as implemented.
                if ( n->attributes()->find(hilti::attribute::kind::AlwaysEmit) )
                    function.defined = true;

                // If the member declaration includes a body mark it as implemented.
                if ( ! fn.empty() && (*fn.begin())->body() )
                    function.defined = true;

                // If the unit is wrapped in a type with a `&cxxname`
                // attribute its members are defined in C++ as well.
                auto* type_ = n->parent<declaration::Type>();

                if ( type_ && type_->attributes()->find(hilti::attribute::kind::Cxxname) )
                    function.defined = true;

                if ( n->type()->type()->as<type::Function>()->flavor() == type::function::Flavor::Hook )
                    function.hook = true;

                if ( auto* type = type_ ) {
                    for ( const auto& requirement :
                          n->attributes()->findAll(hilti::attribute::kind::NeededByFeature) ) {
                        const auto& requirement_ = requirement->valueAsString();
                        const auto& feature = *requirement_;

                        // If no feature constants were collected yet, reschedule us for the next collection pass.
                        //
                        // NOTE: If we emit a `&needed-by-feature` attribute we also always emit a matching feature
                        // constant, so eventually at this point we will see at least one feature constant.
                        if ( features.empty() ) {
                            return;
                        }

                        auto it = features.find(type->type()->type()->typeID());
                        if ( it == features.end() || ! it->second.contains(feature) ) {
                            // This feature requirement has not yet been collected.
                            continue;
                        }

                        function.referenced = function.referenced || it->second.at(feature);
                    }
                }

                break;
            }

            case Stage::PruneUses:
                // Nothing.
                break;

            case Stage::PruneDecls: {
                const auto& function = data.at(function_id);

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
        auto function_id = n->functionID(context());

        switch ( stage ) {
            case Stage::Collect: {
                // Record this function if it is not already known.
                auto& function = data[function_id];

                const auto& fn = n->function();

                // If the declaration contains a function with a body mark the function as defined.
                if ( fn->body() )
                    function.defined = true;

                // If the declaration has a `&cxxname` it is defined in C++.
                else if ( fn->attributes()->find(hilti::attribute::kind::Cxxname) )
                    function.defined = true;

                // If the member declaration is marked `&always-emit` mark it as referenced.
                if ( fn->attributes()->find(hilti::attribute::kind::AlwaysEmit) )
                    function.referenced = true;

                // If the function is public mark is as referenced.
                if ( n->linkage() == declaration::Linkage::Public )
                    function.referenced = true;

                // For implementation of methods check whether the method
                // should only be emitted when certain features are active.
                if ( auto* decl = context()->lookup(n->linkedDeclarationIndex()) ) {
                    for ( const auto& requirement :
                          fn->attributes()->findAll(hilti::attribute::kind::NeededByFeature) ) {
                        const auto& requirement_ = requirement->valueAsString();
                        const auto& feature = *requirement_;

                        // If no feature constants were collected yet, reschedule us for the next collection pass.
                        //
                        // NOTE: If we emit a `&needed-by-feature` attribute we also always emit a matching feature
                        // constant, so eventually at this point we will see at least one feature constant.
                        if ( features.empty() ) {
                            return;
                        }

                        auto it = features.find(decl->fullyQualifiedID());
                        if ( it == features.end() || ! it->second.contains(feature) ) {
                            // This feature requirement has not yet been collected.
                            continue;
                        }

                        // Mark the function as referenced if it is needed by an active feature.
                        function.referenced = function.referenced || it->second.at(feature);
                    }
                }

                if ( fn->ftype()->flavor() == type::function::Flavor::Hook )
                    function.hook = true;

                auto* const decl = context()->lookup(n->linkedDeclarationIndex());

                switch ( fn->ftype()->callingConvention() ) {
                    case type::function::CallingConvention::ExternNoSuspend:
                    case type::function::CallingConvention::Extern: {
                        // If the declaration is `extern` and the unit is `public`, the function
                        // is part of an externally visible API and potentially used elsewhere.

                        if ( decl )
                            function.referenced =
                                function.referenced || decl->linkage() == declaration::Linkage::Public;
                        else
                            function.referenced = true;

                        break;
                    }
                    case type::function::CallingConvention::Standard:
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

            case Stage::PruneUses:
                // Nothing.
                break;

            case Stage::PruneDecls:
                const auto& function = data.at(function_id);

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

        auto* type = n->op0()->type();

        auto* struct_ = type->type()->tryAs<type::Struct>();
        if ( ! struct_ )
            return;

        const auto& member = n->op1()->tryAs<expression::Member>();
        if ( ! member )
            return;

        auto* field = struct_->field(member->id());
        if ( ! field )
            return;

        const auto& function_id = field->fullyQualifiedID();

        if ( ! function_id )
            return;

        switch ( stage ) {
            case Stage::Collect: {
                auto& function = data[function_id];

                function.referenced = true;

                return;
            }

            case Stage::PruneUses: {
                const auto& function = data.at(function_id);

                // Replace call node referencing unimplemented member function with default value.
                if ( ! function.defined ) {
                    if ( n->op0()->type()->type()->isA<type::Struct>() )
                        replaceNode(n, builder()->expressionCtor(builder()->ctorDefault(n->result()->type())),
                                    "replacing call to unimplemented method with default value");
                    return;
                }

                break;
            }

            case Stage::PruneDecls:
                // Nothing.
                break;
        }
    }

    void operator()(operator_::function::Call* n) final {
        if ( ! n->hasOp0() )
            return;

        auto* decl = n->op0()->as<expression::Name>()->resolvedDeclaration();
        if ( ! decl )
            return;

        const auto& function_id = decl->fullyQualifiedID();
        assert(function_id);

        switch ( stage ) {
            case Stage::Collect: {
                auto& function = data[function_id];

                function.referenced = true;
                return;
            }

            case Stage::PruneUses: {
                const auto& function = data.at(function_id);

                // Replace call node referencing unimplemented hook with default value.
                if ( function.hook && ! function.defined ) {
                    if ( auto* fn = decl->tryAs<declaration::Function>() ) {
                        replaceNode(n,
                                    builder()->expressionCtor(
                                        builder()->ctorDefault(fn->function()->ftype()->result()->type())),
                                    "replacing call to unimplemented function with default value");
                        return;
                    }
                }

                break;
            }

            case Stage::PruneDecls:
                // Nothing.
                break;
        }
    }

    void operator()(declaration::Constant* n) final {
        switch ( stage ) {
            case Stage::Collect: {
                std::optional<bool> value;
                if ( auto* ctor = n->value()->tryAs<expression::Ctor>() )
                    if ( auto* bool_ = ctor->ctor()->tryAs<ctor::Bool>() )
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

                features[type_id].insert({feature, *value});
                break;
            }

            case Stage::PruneUses:
            case Stage::PruneDecls: break;
        }
    }
};

struct TypeVisitor : OptimizerVisitor {
    using OptimizerVisitor::OptimizerVisitor;
    using OptimizerVisitor::operator();

    std::map<ID, bool> used;

    void collect(Node* node) override {
        stage = Stage::Collect;

        visitor::visit(*this, node);

        if ( logger().isEnabled(logging::debug::OptimizerCollect) ) {
            HILTI_DEBUG(logging::debug::OptimizerCollect, "types:");
            for ( const auto& [id, used] : used )
                HILTI_DEBUG(logging::debug::OptimizerCollect, util::fmt("    %s: used=%d", id, used));
        }
    }

    bool pruneDecls(Node* node) override {
        stage = Stage::PruneDecls;

        clearModified();
        visitor::visit(*this, node);

        return isModified();
    }

    void operator()(declaration::Field* n) final {
        switch ( stage ) {
            case Stage::Collect: {
                const auto type_id = n->type()->type()->typeID();

                if ( ! type_id )
                    break;

                // Record this type as used.
                used[type_id] = true;

                break;
            }
            case Stage::PruneUses:
            case Stage::PruneDecls:
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

        switch ( stage ) {
            case Stage::Collect:
                // Record the type if not already known. If the type is part of an external API record it as used.
                used.insert({type_id, n->linkage() == declaration::Linkage::Public});
                break;

            case Stage::PruneUses: break;
            case Stage::PruneDecls:
                if ( ! used.at(type_id) ) {
                    removeNode(n, "removing unused type");
                    return;
                }

                break;
        }
    }

    void operator()(type::Name* n) final {
        auto* t = n->resolvedType();
        assert(t);

        switch ( stage ) {
            case Stage::Collect: {
                if ( const auto& type_id = t->typeID() )
                    // Record this type as used.
                    used[type_id] = true;

                break;
            }

            case Stage::PruneUses:
            case Stage::PruneDecls:
                // Nothing.
                break;
        }
    }

    void operator()(UnqualifiedType* n) final {
        if ( n->parent(2)->isA<declaration::Type>() )
            return;

        switch ( stage ) {
            case Stage::Collect: {
                if ( const auto& type_id = n->typeID() )
                    // Record this type as used.
                    used[type_id] = true;

                break;
            }

            case Stage::PruneUses:
            case Stage::PruneDecls:
                // Nothing.
                break;
        }
    }

    void operator()(expression::Name* n) final {
        switch ( stage ) {
            case Stage::Collect: {
                auto* const type = innermostType(n->type());

                const auto& type_id = type->type()->typeID();

                if ( ! type_id )
                    break;

                // Record this type as used.
                used[type_id] = true;

                break;
            }
            case Stage::PruneUses:
            case Stage::PruneDecls:
                // Nothing.
                break;
        }
    }

    void operator()(declaration::Function* n) final {
        switch ( stage ) {
            case Stage::Collect: {
                if ( auto* const decl = context()->lookup(n->linkedDeclarationIndex()) ) {
                    // If this type is referenced by a function declaration it is used.
                    used[decl->fullyQualifiedID()] = true;
                    break;
                }
            }

            case Stage::PruneUses:
            case Stage::PruneDecls:
                // Nothing.
                break;
        }
    }

    void operator()(expression::Type_* n) final {
        switch ( stage ) {
            case Stage::Collect: {
                const auto type_id = n->typeValue()->type()->typeID();
                ;

                if ( ! type_id )
                    break;

                // Record this type as used.
                used[type_id] = true;
                break;
            }

            case Stage::PruneUses:
            case Stage::PruneDecls:
                // Nothing.
                break;
        }
    }
};

struct ConstantFoldingVisitor : OptimizerVisitor {
    using OptimizerVisitor::OptimizerVisitor;
    using OptimizerVisitor::operator();

    std::map<ID, bool> constants;

    void collect(Node* node) override {
        stage = Stage::Collect;

        visitor::visit(*this, node);

        if ( logger().isEnabled(logging::debug::OptimizerCollect) ) {
            HILTI_DEBUG(logging::debug::OptimizerCollect, "constants:");
            std::vector<std::string> xs;
            for ( const auto& [id, value] : constants )
                HILTI_DEBUG(logging::debug::OptimizerCollect, util::fmt("    %s: value=%d", id, value));
        }
    }

    bool pruneUses(Node* node) override {
        stage = Stage::PruneUses;

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

        switch ( stage ) {
            case Stage::Collect: {
                if ( auto* ctor = n->value()->tryAs<expression::Ctor>() )
                    if ( auto* bool_ = ctor->ctor()->tryAs<ctor::Bool>() )
                        constants[id] = bool_->value();

                break;
            }

            case Stage::PruneUses:
            case Stage::PruneDecls: break;
        }
    }

    void operator()(expression::Name* n) final {
        switch ( stage ) {
            case Stage::Collect:
            case Stage::PruneDecls: return;
            case Stage::PruneUses: {
                auto* decl = n->resolvedDeclaration();
                if ( ! decl )
                    return;

                const auto& id = decl->fullyQualifiedID();
                assert(id);

                if ( const auto& constant = constants.find(id); constant != constants.end() ) {
                    if ( n->type()->type()->isA<type::Bool>() ) {
                        replaceNode(n, builder()->bool_((constant->second)), "inlining constant");
                        return;
                    }
                }
            }
        }
    }

    std::optional<bool> tryAsBoolLiteral(Expression* x) {
        if ( auto* expression = x->tryAs<expression::Ctor>() )
            if ( auto* bool_ = expression->ctor()->tryAs<ctor::Bool>() )
                return {bool_->value()};

        return {};
    }

    void operator()(statement::If* n) final {
        switch ( stage ) {
            case Stage::Collect:
            case Stage::PruneDecls: return;
            case Stage::PruneUses: {
                if ( auto bool_ = tryAsBoolLiteral(n->condition()) ) {
                    if ( auto* else_ = n->false_() ) {
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
        switch ( stage ) {
            case OptimizerVisitor::Stage::Collect:
            case OptimizerVisitor::Stage::PruneDecls: return;
            case OptimizerVisitor::Stage::PruneUses: {
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
        switch ( stage ) {
            case Stage::Collect:
            case Stage::PruneDecls: break;
            case Stage::PruneUses: {
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
        switch ( stage ) {
            case Stage::Collect:
            case Stage::PruneDecls: break;
            case Stage::PruneUses: {
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
        switch ( stage ) {
            case Stage::Collect:
            case Stage::PruneDecls: break;
            case Stage::PruneUses: {
                if ( auto op = tryAsBoolLiteral(n->expression()) ) {
                    replaceNode(n, builder()->bool_(! op.value()));
                    return;
                }
            }
        };
    }

    void operator()(statement::While* x) final {
        switch ( stage ) {
            case Stage::Collect:
            case Stage::PruneDecls: return;
            case Stage::PruneUses: {
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

struct ConstantPropagationVisitor : OptimizerVisitor {
    using OptimizerVisitor::OptimizerVisitor;
    using OptimizerVisitor::operator();

    struct ConstantValue {
        Expression* expr = nullptr;
        // NAC
        bool not_a_constant = false;

        bool operator==(const ConstantValue& other) const {
            // If both are NAC, what's in expr doesn't matter
            if ( not_a_constant && other.not_a_constant )
                return true;

            return expr == other.expr && not_a_constant == other.not_a_constant;
        }
    };

    using ConstantMap = std::map<Declaration*, ConstantValue>;
    struct AnalysisResult {
        detail::cfg::CFG cfg;
        std::map<detail::cfg::GraphNode, ConstantMap> in;
        std::map<detail::cfg::GraphNode, ConstantMap> out;
    };

    std::map<Node*, AnalysisResult> analysis_results;

    void collect(Node* node) override {
        stage = Stage::Collect;
        visitor::visit(*this, node);
    }

    bool pruneUses(Node* node) override {
        stage = Stage::PruneUses;

        clearModified();
        visitor::visit(*this, node);

        return isModified();
    }

    void transfer(const detail::cfg::GraphNode& n, ConstantMap& new_out) {
        // Marks all children that are names as not a constant in the given map.
        // This is used by function calls, since they have deeply nested names
        // that should all be marked NAC.
        struct NameNACer : hilti::visitor::PreOrder {
            ConstantMap& constants;
            NameNACer(ConstantMap& constants) : constants(constants) {}
            void operator()(expression::Name* name) override {
                if ( auto* decl = name->resolvedDeclaration() ) {
                    constants[decl].not_a_constant = true;
                }
            }
        };

        struct TransferVisitor : hilti::visitor::PreOrder {
            ConstantMap& constants;
            NameNACer name_nac;

            TransferVisitor(ConstantMap& constants) : constants(constants), name_nac(constants) {}

            // Tries to evaluate an expression to a constant value given a map of known constants.
            Expression* evaluate(Expression* expr) {
                if ( expr->isConstant() && expr->isA<expression::Ctor>() )
                    return expr;

                if ( auto* name = expr->tryAs<expression::Name>() ) {
                    if ( auto* decl = name->resolvedDeclaration(); decl && constants.contains(decl) ) {
                        const auto& val = constants.at(decl);
                        if ( val.not_a_constant )
                            return nullptr;

                        return val.expr;
                    }
                }

                // TODO: This would be nice for folding operators
                return nullptr;
            }

            void operator()(expression::Assign* assign) override {
                if ( auto* name = assign->target()->tryAs<expression::Name>() ) {
                    if ( auto* decl = name->resolvedDeclaration() ) {
                        auto* const_val = evaluate(assign->source());
                        constants[decl] = {.expr = const_val, .not_a_constant = const_val == nullptr};
                    }
                }
            }

            void operator()(declaration::LocalVariable* decl) override {
                if ( auto* init = decl->init() ) {
                    auto* const_val = evaluate(init);
                    constants[decl] = {.expr = const_val, .not_a_constant = const_val == nullptr};
                }
            }

            void operator()(operator_::struct_::MemberCall* op) override {
                // NAC anything used in a call; unfortunately they may silently
                // coerce to a reference.
                visitor::visit(name_nac, op);
            }

            void operator()(operator_::function::Call* op) override {
                // NAC anything used in a call; unfortunately they may silently
                // coerce to a reference.
                visitor::visit(name_nac, op);
            }

            void operator()(expression::ResolvedOperator* op) override {
                auto sig = op->operator_().signature();
                std::size_t i = 0;
                for ( const auto* operand : sig.operands->operands() ) {
                    if ( operand->kind() == parameter::Kind::InOut )
                        // NAC any names within
                        visitor::visit(name_nac, op->operands()[i]);
                    i++;
                }
            }
        };

        TransferVisitor tv(new_out);
        visitor::visit(tv, n.value());
    }

    void populateDataflow(AnalysisResult& result, const ConstantMap& init, const ID& function_name) {
        auto worklist = result.cfg.postorder();
        // We always expect the worklist to contain begin/end nodes
        assert(worklist.size() >= 1);
        // Reverse postorder is best for forward analyses
        std::ranges::reverse(worklist);

        // Set the initial state from parameters
        result.out[worklist.front()] = init;
        worklist.pop_front();

        auto num_processed = 0;

        while ( ! worklist.empty() ) {
            auto n = worklist.front();
            worklist.pop_front();

            // Meet
            ConstantMap new_in;
            auto preds = result.cfg.graph().neighborsUpstream(n->identity());
            for ( const uint64_t& pred : preds ) {
                const auto& pred_out = result.out[*result.cfg.graph().getNode(pred)];

                for ( const auto& [decl, const_val] : pred_out ) {
                    // Add if we can, otherwise NAC if they're not the same const.
                    auto [found, inserted] = new_in.try_emplace(decl, const_val);
                    if ( ! inserted && found->second != const_val )
                        found->second.not_a_constant = true;
                }
            }

            result.in[n] = std::move(new_in);

            // Transfer
            ConstantMap new_out = result.in[n];
            transfer(n, new_out);

            // If it changed, add successors to worklist
            ConstantMap old_out = result.out[n];
            if ( old_out != new_out ) {
                result.out[n] = new_out;
                for ( auto succ_id : result.cfg.graph().neighborsDownstream(n->identity()) ) {
                    const auto* succ_node = result.cfg.graph().getNode(succ_id);
                    if ( std::ranges::find(worklist, *succ_node) == worklist.end() )
                        worklist.push_back(*succ_node);
                }
            }
            num_processed++;
        }

        HILTI_DEBUG(logging::debug::OptimizerCollect,
                    util::fmt("function %s took %d iterations before constant propagation convergence", function_name,
                              num_processed));
    }

    void applyPropagation(Statement* body, const AnalysisResult& result) {
        struct Replacer : visitor::MutatingPreOrder {
            using visitor::MutatingPreOrder::MutatingPreOrder;

            const AnalysisResult& result;
            Replacer(Builder* builder, const AnalysisResult& result)
                : visitor::MutatingPreOrder(builder, logging::debug::Optimizer), result(result) {}

            // Helper to find the CFG node for an AST node.
            const detail::cfg::GraphNode* findCFGNode(Node* n) {
                for ( auto* p = n; p; p = p->parent() ) {
                    if ( const auto* graph_node = result.cfg.graph().getNode(p->identity()) )
                        return graph_node;
                }
                return nullptr;
            }

            bool isLHSOfAssign(Expression* expr) {
                for ( auto* parent = expr->parent(); parent; parent = parent->parent() ) {
                    // Don't propagate to the LHS of an assignment
                    if ( auto* assign = parent->tryAs<operator_::tuple::CustomAssign>() ) {
                        if ( assign->op0() == expr )
                            return true;
                    }
                    if ( auto* assign = parent->tryAs<expression::Assign>() ) {
                        if ( assign->target() == expr )
                            return true;
                    }
                }

                return false;
            }

            void operator()(expression::Name* n) override {
                if ( isLHSOfAssign(n) )
                    return;

                const auto* cfg_node = findCFGNode(n);
                if ( ! cfg_node )
                    return;

                auto in_it = result.in.find(*cfg_node);
                auto out_it = result.out.find(*cfg_node);
                if ( in_it == result.in.end() || out_it == result.out.end() )
                    return;

                auto* decl = n->resolvedDeclaration();
                if ( ! decl )
                    return;

                const auto& constants = in_it->second;
                const auto& out_constants = out_it->second;
                auto const_it = constants.find(decl);
                auto out_const_it = out_constants.find(decl);
                if ( const_it == constants.end() || out_const_it == out_constants.end() )
                    return;

                // If they aren't the same, something changed within the statement.
                // Since we're not sure which comes first, just abort.
                if ( const_it->second != out_const_it->second )
                    return;

                auto const_val = const_it->second;

                if ( ! const_val.not_a_constant ) {
                    recordChange(n, util::fmt("propagating constant value in %s", n->id()));
                    replaceNode(n, node::detail::deepcopy(context(), const_val.expr, true));
                }
            }
        };

        Replacer replacer(builder(), result);
        visitor::visit(replacer, body);
        if ( replacer.isModified() )
            recordChange(body, "constant propagation");
    }

    void operator()(declaration::Function* n) override {
        switch ( stage ) {
            case Stage::Collect:
                if ( auto* body = n->function()->body() ) {
                    AnalysisResult result((detail::cfg::CFG(body)));
                    ConstantMap init;
                    for ( auto* param : n->function()->ftype()->parameters() )
                        init[param].not_a_constant = true;
                    populateDataflow(result, init, n->id());
                    analysis_results.insert({body, std::move(result)});
                }
                break;
            case Stage::PruneUses:
                if ( auto* body = n->function()->body(); body && analysis_results.contains(body) )
                    applyPropagation(body, analysis_results.at(body));
                break;
            case Stage::PruneDecls: break;
        }
    }
};

/**
 * Visitor running on the final, optimized AST to perform additional peephole
 * optimizations. Will run repeatedly until it performs no further changes.
 */
struct PeepholeOptimizer : visitor::MutatingPostOrder {
    using visitor::MutatingPostOrder::MutatingPostOrder;

    // Returns true if statement is `(*self).__error = __error`.
    bool isErrorPush(statement::Expression* n) {
        auto* assign = n->expression()->tryAs<expression::Assign>();
        if ( ! assign )
            return false;

        auto* lhs = assign->target()->tryAs<operator_::struct_::MemberNonConst>();
        if ( ! lhs )
            return false;

        auto* op0 = lhs->op0();
        operator_::value_reference::Deref* deref0 = nullptr;
        while ( true ) {
            if ( auto* x = op0->tryAs<operator_::value_reference::Deref>() ) {
                deref0 = x;
                break;
            }
            else if ( auto* x = op0->tryAs<expression::Grouping>() ) {
                op0 = x->expression();
                continue;
            }

            return false;
        }
        assert(deref0);

        auto* op1 = lhs->op1()->tryAs<expression::Member>();
        if ( ! (op1 && op1->id() == "__error") )
            return false;

        auto* self = deref0->op0()->tryAs<expression::Name>();
        if ( ! (self && self->id() == "self") )
            return false;

        auto* rhs = assign->source()->tryAs<expression::Name>();
        if ( ! (rhs && rhs->id() == "__error") )
            return false;

        return true;
    }

    // Returns true if statement is `__error == (*self).__error`.
    bool isErrorPop(statement::Expression* n) {
        auto* assign = n->expression()->tryAs<expression::Assign>();
        if ( ! assign )
            return false;

        auto* lhs = assign->target()->tryAs<expression::Name>();
        if ( ! (lhs && lhs->id() == "__error") )
            return false;

        auto* rhs = assign->source()->tryAs<operator_::struct_::MemberNonConst>();
        if ( ! rhs )
            return false;

        auto* op0 = rhs->op0();
        operator_::value_reference::Deref* deref0 = nullptr;
        while ( true ) {
            if ( auto* x = op0->tryAs<operator_::value_reference::Deref>() ) {
                deref0 = x;
                break;
            }
            else if ( auto* x = op0->tryAs<expression::Grouping>() ) {
                op0 = x->expression();
                continue;
            }

            return false;
        }
        assert(deref0);

        auto* op1 = rhs->op1()->tryAs<expression::Member>();
        if ( ! (op1 && op1->id() == "__error") )
            return false;

        auto* self = deref0->op0()->tryAs<expression::Name>();
        if ( ! (self && self->id() == "self") )
            return false;

        return true;
    }

    void operator()(statement::Expression* n) final {
        // Remove expression statements of the form `default<void>`.
        if ( auto* ctor = n->expression()->tryAs<expression::Ctor>();
             ctor && ctor->ctor()->isA<ctor::Default>() && ctor->type()->type()->isA<type::Void>() ) {
            recordChange(n, "removing default<void> statement");
            n->parent()->removeChild(n);
            return;
        }

        // Remove statement pairs of the form:
        //
        //    (*self).__error = __error;
        //    __error = (*self).__error;
        //
        // These will be left behind by the optimizer if a hook call got
        // optimized out in between them.
        if ( isErrorPush(n) && n->parent() ) {
            auto* parent = n->parent();
            if ( auto* sibling = parent->sibling(n) ) {
                if ( auto* stmt = sibling->tryAs<statement::Expression>(); stmt && isErrorPop(stmt) ) {
                    recordChange(n, "removing unneeded error push/pop statements");
                    parent->removeChild(n);
                    parent->removeChild(sibling);
                    return;
                }
            }
        }
    }

    void operator()(statement::Try* n) final {
        // If a there's only a single catch block that just rethrows, replace
        // the whole try/catch with the block inside.
        if ( auto catches = n->catches(); catches.size() == 1 ) {
            const auto& catch_ = catches.front();
            if ( auto* catch_body = catch_->body()->as<statement::Block>(); catch_body->statements().size() == 1 ) {
                if ( auto* throw_ = catch_body->statements().front()->tryAs<statement::Throw>();
                     throw_ && ! throw_->expression() ) {
                    recordChange(n, "replacing rethrowing try/catch with just the block");
                    replaceNode(n, n->body());
                    return;
                }
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
    std::map<ID, Features> features;

    enum class Stage { COLLECT, TRANSFORM };
    Stage stage = Stage::COLLECT;

    void collect(Node* node) {
        stage = Stage::COLLECT;

        visitor::visit(*this, node);

        if ( logger().isEnabled(logging::debug::OptimizerCollect) ) {
            HILTI_DEBUG(logging::debug::OptimizerCollect, "feature requirements:");
            for ( const auto& [id, features] : features ) {
                std::stringstream ss;
                ss << "    " << id << ':';
                for ( const auto& [feature, enabled] : features )
                    ss << util::fmt(" %s=%d", feature, enabled);
                HILTI_DEBUG(logging::debug::OptimizerCollect, ss.str());
            }
        }
    }

    void transform(Node* node) {
        stage = Stage::TRANSFORM;
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

        switch ( stage ) {
            case Stage::COLLECT: {
                // Record the feature as unused for the type if it was not already recorded.
                features[type_id].insert({feature, false});
                break;
            }

            case Stage::TRANSFORM: {
                const auto required = features.at(type_id).at(feature);
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
        switch ( stage ) {
            case Stage::COLLECT: {
                // Collect parameter requirements from the declaration of the called function.
                std::vector<std::set<std::string>> requirements;

                auto* rid = n->op0()->tryAs<expression::Name>();
                if ( ! rid )
                    return;

                auto* decl = rid->resolvedDeclaration();
                if ( ! decl )
                    return;

                const auto& fn = decl->tryAs<declaration::Function>();
                if ( ! fn )
                    return;

                for ( const auto& parameter : fn->function()->ftype()->parameters() ) {
                    // The requirements of this parameter.
                    std::set<std::string> reqs;

                    for ( const auto& requirement :
                          parameter->attributes()->findAll(hilti::attribute::kind::RequiresTypeFeature) ) {
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
                    auto* type = innermostType(arg->type());

                    // Ignore arguments types without type ID (e.g., builtin types).
                    const auto& type_id = type->type()->typeID();
                    if ( ! type_id ) {
                        ++i;
                        continue;
                    }

                    for ( const auto& requirement : requirements[i] ) {
                        if ( ! ignored_features.contains(type_id) ||
                             ! ignored_features.at(type_id).contains(requirement) )
                            // Enable the required feature.
                            features[type_id][requirement] = true;
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
        switch ( stage ) {
            case Stage::COLLECT: {
                auto* type = n->op0()->type();
                while ( type->type()->isReferenceType() )
                    type = type->type()->dereferencedType();

                auto* const struct_ = type->type()->tryAs<type::Struct>();
                if ( ! struct_ )
                    break;

                const auto& member = n->op1()->as<expression::Member>();

                auto* const field = struct_->field(member->id());
                if ( ! field )
                    break;

                const auto ignored_features = conditionalFeatures(n);

                // Check if access to the field has type requirements.
                if ( auto type_id = type->type()->typeID() )
                    for ( const auto& requirement :
                          field->attributes()->findAll(hilti::attribute::kind::NeededByFeature) ) {
                        const auto feature = *requirement->valueAsString();
                        if ( ! ignored_features.contains(type_id) || ! ignored_features.at(type_id).contains(feature) )
                            // Enable the required feature.
                            features[type_id][*requirement->valueAsString()] = true;
                    }

                // Check if call imposes requirements on any of the types of the arguments.
                const auto& op = static_cast<const struct_::MemberCall&>(n->operator_());
                assert(op.declaration());
                auto* ftype = op.declaration()->type()->type()->as<type::Function>();

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
                    auto* const type = innermostType(args[i]->type());
                    const auto& param = parameters[i];

                    if ( auto type_id = type->type()->typeID() )
                        for ( const auto& requirement :
                              param->attributes()->findAll(hilti::attribute::kind::RequiresTypeFeature) ) {
                            const auto feature = *requirement->valueAsString();
                            if ( ! ignored_features.contains(type_id) ||
                                 ! ignored_features.at(type_id).contains(feature) ) {
                                // Enable the required feature.
                                features[type_id][feature] = true;
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
        auto id_feature_from_constant = [](const ID& feature_constant) -> std::optional<std::pair<ID, std::string>> {
            // Split away the module part of the resolved ID.
            auto id = util::split1(feature_constant, "::").second;

            if ( ! util::startsWith(id, "__feat") )
                return {};

            const auto& tokens = util::split(std::move(id), "%");
            assert(tokens.size() == 3);

            auto type_id = ID(util::replace(tokens[1], "@@", "::"));
            const auto& feature = tokens[2];

            return {{type_id, feature}};
        };

        if ( auto* rid = condition->tryAs<expression::Name>() ) {
            if ( auto id_feature = id_feature_from_constant(rid->id()) )
                result[std::move(id_feature->first)].insert(std::move(id_feature->second));
        }

        // If we did not find a feature constant in the conditional, we
        // could also be dealing with a `OR` of feature constants.
        else if ( auto* or_ = condition->tryAs<expression::LogicalOr>() ) {
            featureFlagsFromCondition(or_->op0(), result);
            featureFlagsFromCondition(or_->op1(), result);
        }
    }

    // Helper function to compute the set of feature flags wrapping the given position.
    static std::map<ID, std::set<std::string>> conditionalFeatures(Node* n) {
        std::map<ID, std::set<std::string>> result;

        // We walk up the full path to discover all feature conditionals wrapping this position.
        for ( auto* parent = n->parent(); parent; parent = parent->parent() ) {
            if ( const auto& if_ = parent->tryAs<statement::If>() ) {
                auto* const condition = if_->condition();
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
        switch ( stage ) {
            case Stage::COLLECT: {
                auto* type_ = x->op0()->type();
                while ( type_->type()->isReferenceType() )
                    type_ = type_->type()->dereferencedType();

                auto type_id = type_->type()->typeID();
                if ( ! type_id )
                    return;

                auto* member = x->op1()->tryAs<expression::Member>();
                if ( ! member )
                    return;

                auto lookup = scope::lookupID<declaration::Type>(type_id, x, "type");
                if ( ! lookup )
                    return;

                auto* type = lookup->first->template as<declaration::Type>();
                auto* struct_ = type->type()->type()->template tryAs<type::Struct>();
                if ( ! struct_ )
                    return;

                auto* field = struct_->field(member->id());
                if ( ! field )
                    return;

                const auto ignored_features = conditionalFeatures(x);

                for ( const auto& requirement :
                      field->attributes()->findAll(hilti::attribute::kind::NeededByFeature) ) {
                    const auto feature = *requirement->valueAsString();

                    // Enable the required feature if it is not ignored here.
                    if ( ! ignored_features.contains(type_id) || ! ignored_features.at(type_id).contains(feature) )
                        features[type_id][feature] = true;
                }

                break;
            }
            case Stage::TRANSFORM:
                // Nothing.
                break;
        }
    }

    void operator()(operator_::struct_::MemberConst* n) final { handleMemberAccess(n); }
    void operator()(operator_::struct_::MemberNonConst* n) final { handleMemberAccess(n); }

    void operator()(declaration::Type* n) final {
        switch ( stage ) {
            case Stage::COLLECT: {
                // Collect feature requirements associated with type.
                for ( const auto& requirement : n->attributes()->findAll(hilti::attribute::kind::RequiresTypeFeature) )
                    features[n->typeID()][*requirement->valueAsString()] = true;

                break;
            }

            case Stage::TRANSFORM: {
                if ( ! features.contains(n->fullyQualifiedID()) )
                    break;

                // Add type comment documenting enabled features.
                auto meta = n->meta();
                auto comments = meta.comments();

                if ( auto enabled_features = util::filter(features.at(n->fullyQualifiedID()),
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
    using OptimizerVisitor::operator();

    // Map tracking whether a member is used in the code.
    std::map<std::string, bool> used;

    // Map tracking for each type which features are enabled.
    std::map<ID, std::map<std::string, bool>> features;

    void collect(Node* node) override {
        stage = Stage::Collect;

        visitor::visit(*this, node);

        if ( logger().isEnabled(logging::debug::OptimizerCollect) ) {
            HILTI_DEBUG(logging::debug::OptimizerCollect, "members:");

            HILTI_DEBUG(logging::debug::OptimizerCollect, "    feature status:");
            for ( const auto& [id, features] : features ) {
                std::stringstream ss;
                ss << "        " << id << ':';
                for ( const auto& [feature, enabled] : features )
                    ss << util::fmt(" %s=%d", feature, enabled);
                HILTI_DEBUG(logging::debug::OptimizerCollect, ss.str());
            }

            for ( const auto& [id, used] : used )
                HILTI_DEBUG(logging::debug::OptimizerCollect, util::fmt("    %s used=%d", id, used));
        }
    }

    bool pruneDecls(Node* node) override {
        stage = Stage::PruneDecls;

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
        if ( n->attributes()->find(hilti::attribute::kind::AlwaysEmit) )
            return;

        // We only remove member marked `&internal`.
        if ( ! n->attributes()->find(hilti::attribute::kind::Internal) )
            return;

        auto member_id = util::join({type_id, n->id()}, "::");

        switch ( stage ) {
            case Stage::Collect: {
                // Record the member if it is not yet known.
                used.insert({member_id, false});
                break;
            }

            case Stage::PruneDecls: {
                if ( ! used.at(member_id) ) {
                    // Check whether the field depends on an active feature in which case we do not remove the
                    // field.
                    if ( features.contains(type_id) ) {
                        const auto& features_ = features.at(type_id);

                        auto dependent_features =
                            hilti::node::transform(n->attributes()->findAll(hilti::attribute::kind::NeededByFeature),
                                                   [](const auto& attr) { return *attr->valueAsString(); });

                        for ( const auto& dependent_feature_ :
                              n->attributes()->findAll(hilti::attribute::kind::NeededByFeature) ) {
                            auto dependent_feature = *dependent_feature_->valueAsString();

                            // The feature flag is known and the feature is active.
                            if ( features_.contains(dependent_feature) && features_.at(dependent_feature) )
                                return; // Use `return` instead of `break` here to break out of `switch`.
                        }
                    }

                    removeNode(n, "removing unused member");
                    return;
                }
            }
            case Stage::PruneUses:
                // Nothing.
                break;
        }
    }

    void operator()(expression::Member* n) final {
        switch ( stage ) {
            case Stage::Collect: {
                auto* expr = n->parent()->children()[1]->tryAs<Expression>();
                if ( ! expr )
                    break;

                auto* const type = innermostType(expr->type());

                auto* struct_ = type->type()->tryAs<type::Struct>();
                if ( ! struct_ )
                    break;

                auto type_id = type->type()->typeID();
                if ( ! type_id )
                    break;

                auto member_id = util::join({std::move(type_id), n->id()}, "::");

                // Record the member as used.
                used[member_id] = true;
                break;
            }
            case Stage::PruneUses:
            case Stage::PruneDecls: break;
        }
    }

    void operator()(expression::Name* n) final {
        switch ( stage ) {
            case Stage::Collect: {
                auto* decl = n->resolvedDeclaration();
                if ( ! decl || ! decl->isA<declaration::Field>() )
                    return;

                // Record the member as used.
                used[n->id()] = true;
                break;
            }
            case Stage::PruneUses:
            case Stage::PruneDecls:
                // Nothing.
                break;
        }
    }

    void operator()(declaration::Constant* n) final {
        switch ( stage ) {
            case Stage::Collect: {
                // Check whether the feature flag matches the type of the field.
                if ( ! util::startsWith(n->id(), "__feat%") )
                    break;

                auto tokens = util::split(n->id(), "%");
                assert(tokens.size() == 3);

                auto type_id = ID(tokens[1]);
                const auto& feature = tokens[2];
                auto is_active = n->value()->as<expression::Ctor>()->ctor()->as<ctor::Bool>()->value();

                type_id = ID(util::replace(type_id, "@@", "::"));
                features[type_id][feature] = is_active;

                break;
            }
            case Stage::PruneUses:
            case Stage::PruneDecls:
                // Nothing.
                break;
        }
    }
};

/** Removes unused function parameters. */
struct FunctionParamVisitor : OptimizerVisitor {
    using OptimizerVisitor::OptimizerVisitor;
    using OptimizerVisitor::operator();

    struct UnusedParams {
        // Vector of positions for unused parameters
        std::vector<std::size_t> unused_params;
        // Whether or not we removed arguments from uses yet
        bool removed_uses = false;
    };

    // The unused parameters for a given function ID
    std::map<ID, UnusedParams> fn_unused_params;

    void collect(Node* node) override {
        fn_unused_params.clear();
        stage = Stage::Collect;

        visitor::visit(*this, node);
    }

    bool pruneUses(Node* node) override {
        stage = Stage::PruneUses;

        clearModified();
        visitor::visit(*this, node);

        return isModified();
    }

    bool pruneDecls(Node* node) override {
        stage = Stage::PruneDecls;

        clearModified();
        visitor::visit(*this, node);

        return isModified();
    }

    void removeArgs(expression::ResolvedOperator* call, const std::vector<std::size_t>& positions) {
        if ( ! call->isA<operator_::function::Call>() && ! call->isA<operator_::struct_::MemberCall>() )
            logger().fatalError(util::fmt("expected Call or MemberCall node, but got %s", call->typename_()));

        if ( positions.empty() )
            return;

        bool is_method = call->isA<operator_::struct_::MemberCall>();

        // Get the params as a tuple
        auto* ctor = is_method ? call->op2()->as<expression::Ctor>() : call->op1()->as<expression::Ctor>();
        auto* tup = ctor->ctor()->as<ctor::Tuple>();

        // Make new parameters
        Expressions params;
        for ( std::size_t i = 0; i < tup->value().size(); i++ ) {
            if ( std::ranges::find(positions, i) == positions.end() )
                params.push_back(tup->value()[i]);
        }

        auto* ntuple = builder()->expressionCtor(builder()->ctorTuple(params));
        if ( is_method )
            replaceNode(call->op2(), ntuple, "removing unused arguments from method call");
        else
            replaceNode(call->op1(), ntuple, "removing unused arguments from call");
    }

    void pruneFromUses(const ID& function_id, const Operator* op) {
        auto unused = fn_unused_params.at(function_id);
        if ( unused.removed_uses || unused.unused_params.empty() || ! op )
            return;

        const auto* uses_of_op = uses(op);

        if ( ! uses_of_op )
            return;

        for ( auto* use : *uses_of_op ) {
            if ( ! use )
                continue;
            removeArgs(use, unused.unused_params);
        }

        unused.removed_uses = true;
    }

    void pruneFromDecl(const ID& function_id, type::Function* ftype) {
        auto unused = fn_unused_params.at(function_id);
        if ( unused.unused_params.empty() )
            return;

        auto params = ftype->parameters();

        // Ensure they're sorted in descending order so we remove from the back.
        std::ranges::sort(unused.unused_params, std::greater<>());
        for ( std::size_t index : unused.unused_params ) {
            assert(index < params.size());
            params.erase(params.begin() + static_cast<std::ptrdiff_t>(index));
        }

        recordChange(ftype, "removing unused function parameters");
        ftype->setParameters(builder()->context(), params);
    }

    /**
     * Determines if the uses of this operator contain any side effects.
     * Currently, this means a function call that contains another function
     * call as an argument.
     */
    bool usesContainSideEffects(const Operator* op) {
        const auto* uses_of_op = uses(op);
        if ( ! uses_of_op )
            return false;

        for ( auto* use : *uses_of_op ) {
            if ( ! use->isA<operator_::function::Call>() && ! use->isA<operator_::struct_::MemberCall>() )
                continue;

            bool is_method = use->isA<operator_::struct_::MemberCall>();

            // Get the params as a tuple
            auto* ctor = is_method ? use->op2()->tryAs<expression::Ctor>() : use->op1()->tryAs<expression::Ctor>();
            if ( ! ctor )
                continue;

            auto* tup = ctor->ctor()->tryAs<ctor::Tuple>();
            if ( ! tup )
                continue;

            for ( auto* arg : tup->value() ) {
                if ( arg->isA<operator_::function::Call>() )
                    return true;
            }
        }

        return false;
    }

    void operator()(declaration::Function* n) final {
        auto function_id = n->functionID(context());

        switch ( stage ) {
            case Stage::Collect: {
                if ( fn_unused_params.contains(function_id) )
                    return;

                // Create the unused params
                auto& unused = fn_unused_params[function_id];

                if ( n->linkage() == declaration::Linkage::Public )
                    return;

                auto all_lookups = context()->root()->scope()->lookupAll(n->fullyQualifiedID());
                // Don't set if there's no body or multiple implementations
                if ( ! n->function()->body() ||
                     (all_lookups.size() > 1 && n->function()->ftype()->flavor() != type::function::Flavor::Hook) )
                    return;

                // Don't set if a use may have side effects
                if ( usesContainSideEffects(n->operator_()) )
                    return;

                for ( std::size_t i = 0; i < n->function()->ftype()->parameters().size(); i++ )
                    unused.unused_params.push_back(i);

                break;
            }

            case Stage::PruneUses: {
                pruneFromUses(function_id, n->operator_());
                break;
            }
            case Stage::PruneDecls: {
                pruneFromDecl(function_id, n->function()->ftype());
                break;
            }
        }
    }

    void operator()(declaration::Field* n) final {
        auto* ftype = n->type()->type()->tryAs<type::Function>();
        if ( ! ftype || ! n->parent()->isA<type::Struct>() )
            return;

        const auto& function_id = n->fullyQualifiedID();

        switch ( stage ) {
            case Stage::Collect: {
                if ( fn_unused_params.contains(function_id) )
                    return;

                // Create the unused params
                auto& unused = fn_unused_params[function_id];

                if ( n->attributes()->find(hilti::attribute::kind::Cxxname) ||
                     n->attributes()->find(hilti::attribute::kind::AlwaysEmit) ||
                     n->attributes()->find(hilti::attribute::kind::Public) )
                    return;

                if ( n->linkage() == declaration::Linkage::Public )
                    return;

                // If the type is public, we cannot change its fields.
                auto* type_ = n->parent<declaration::Type>();
                if ( type_ && type_->linkage() == declaration::Linkage::Public )
                    return;

                // Don't set if a use may have side effects
                if ( usesContainSideEffects(n->operator_()) )
                    return;

                for ( std::size_t i = 0; i < ftype->parameters().size(); i++ )
                    unused.unused_params.push_back(i);

                break;
            }

            case Stage::PruneUses: {
                pruneFromUses(function_id, n->operator_());
                break;
            }
            case Stage::PruneDecls: {
                pruneFromDecl(function_id, ftype);
                break;
            }
        }
    }

    std::optional<std::tuple<type::Function*, ID>> enclosingFunction(Node* n) {
        for ( auto* current = n->parent(); current; current = current->parent() ) {
            if ( auto* fn_decl = current->tryAs<declaration::Function>() ) {
                return std::tuple(fn_decl->function()->ftype(), fn_decl->functionID(context()));
            }
            else if ( auto* field = current->tryAs<declaration::Field>(); field && field->inlineFunction() ) {
                return std::tuple(field->inlineFunction()->ftype(), field->fullyQualifiedID());
            }
        }

        return {};
    }

    /** Removes the param_id as used within the function. */
    void removeUsed(type::Function* ftype, const ID& function_id, const ID& param_id) {
        auto& unused = fn_unused_params.at(function_id);

        for ( auto it = unused.unused_params.begin(); it != unused.unused_params.end(); ++it ) {
            auto param_num = *it;
            assert(ftype->parameters().size() >= param_num);
            if ( ftype->parameters()[param_num]->id() == param_id ) {
                unused.unused_params.erase(it, std::next(it));
                return;
            }
        }
    }

    void operator()(expression::Name* n) final {
        auto opt_enclosing_fn = enclosingFunction(n);
        if ( ! opt_enclosing_fn )
            return;

        auto [ftype, function_id] = *opt_enclosing_fn;

        switch ( stage ) {
            case Stage::Collect: {
                auto& unused = fn_unused_params.at(function_id);
                if ( unused.unused_params.size() == 0 )
                    return;

                removeUsed(ftype, function_id, n->id());
            }
            case Stage::PruneUses: return;
            case Stage::PruneDecls: return;
        }
    }

    void operator()(expression::Keyword* n) final {
        auto opt_enclosing_fn = enclosingFunction(n);
        if ( ! opt_enclosing_fn )
            return;

        auto [ftype, function_id] = *opt_enclosing_fn;
        switch ( stage ) {
            case Stage::Collect:
                // Only apply to captures, everything else seems handled by Name.
                if ( n->kind() == expression::keyword::Kind::Captures )
                    removeUsed(ftype, function_id, "__captures");
                return;
            case Stage::PruneUses:
            case Stage::PruneDecls: return;
        }
    }
};

struct FunctionBodyVisitor : OptimizerVisitor {
    using OptimizerVisitor::OptimizerVisitor;

    std::unordered_set<Node*> unreachableNodes(const detail::cfg::CFG& cfg) const;

    std::vector<Node*> unusedStatements(const detail::cfg::CFG& cfg) const;

    bool pruneUses(Node* node) override {
        visitor::visit(*this, node);
        return isModified();
    }

    // Remove a given AST node from both the AST and the CFG.
    bool remove(detail::cfg::CFG& cfg, Node* data, const std::string& msg = {}) {
        assert(data);

        Node* node = nullptr;

        if ( data->isA<Statement>() && data->hasParent() )
            node = data;

        else if ( data->isA<Expression>() ) {
            auto* p = data->parent();

            while ( p && ! p->isA<Statement>() )
                p = p->parent();

            if ( p && p->hasParent() )
                node = p;
        }

        else if ( data->isA<Declaration>() ) {
            if ( auto* stmt = data->parent(); stmt && stmt->isA<statement::Declaration>() )
                node = stmt;
        }

        if ( node ) {
            // Edit AST.
            removeNode(node, msg);

            // Make equivalent edit to control flow graph.
            cfg.removeNode(node);

            return true;
        }

        return false;
    }

    void visitNode(Node* n) {
        while ( true ) {
            bool modified = false;

            // TODO(bbannier): In principal we should be able to reuse the
            // flow through optimizations, but this currently fails due to
            // edits not correctly changing the flow.
            auto cfg = detail::cfg::CFG(n);

            for ( auto* x : unusedStatements(cfg) )
                modified |= remove(cfg, x, "statement result unused");

            if ( modified )
                break;

            auto unreachable_nodes = unreachableNodes(cfg);

            // Remove unreachable control flow branches.
            // NOLINTNEXTLINE(bugprone-nondeterministic-pointer-iteration-order)
            for ( auto* n : unreachable_nodes )
                modified |= remove(cfg, n, "unreachable code");

            if ( ! modified )
                break;
        }
    }

    void operator()(declaration::Function* f) override {
        if ( auto* body = f->function()->body() )
            visitNode(body);
    }

    void operator()(declaration::Module* m) override {
        OptimizerVisitor::operator()(m);

        if ( auto* body = m->statements() )
            visitNode(body);
    }
};

std::vector<Node*> FunctionBodyVisitor::unusedStatements(const detail::cfg::CFG& cfg) const {
    // This can only be called after dataflow information has been populated.
    const auto& dataflow = cfg.dataflow();
    assert(! dataflow.empty());

    std::map<detail::cfg::GraphNode, uint64_t> uses;

    // Loop over all nodes.
    for ( const auto& [n, transfer] : dataflow ) {
        // Check whether we want to declare any of the statements used. We currently do this for
        // - `inout` parameters since their result is can be seen after the function has ended,
        // - globals since they could be used elsewhere without us being able to see it,
        // - `self` expression since they live on beyond the current block.
        if ( n->isA<detail::cfg::End>() ) {
            assert(dataflow.contains(n));
            // If we saw an operation an `inout` parameter at the end of the flow, mark the parameter as used.
            // For each incoming statement ...
            for ( const auto& [decl, stmts] : transfer.in ) {
                // If the statement generated an update to the value ...
                bool mark_used = false;

                if ( decl->isA<declaration::GlobalVariable>() )
                    mark_used = true;

                else if ( auto* p = decl->tryAs<declaration::Parameter>();
                          p && (p->kind() == parameter::Kind::InOut || p->type()->type()->isAliasingType()) )
                    mark_used = true;

                else if ( const auto* expr = decl->tryAs<declaration::Expression>() ) {
                    if ( auto* keyword = expr->expression()->tryAs<expression::Keyword>();
                         keyword && keyword->kind() == expression::keyword::Kind::Self )
                        mark_used = true;
                }

                if ( mark_used ) {
                    for ( const auto& stmt : stmts )
                        ++uses[stmt];
                }
            }
        }

        if ( ! n->isA<detail::cfg::MetaNode>() )
            (void)uses[n]; // Record statement if not already known.

        // For each update to a declaration generated by a node ...
        for ( const auto& [decl, stmt] : transfer.gen ) {
            // Search for nodes using the statement.
            for ( const auto& [n_, t] : dataflow ) {
                // Skip the original node.
                if ( n_ == n )
                    continue;

                // If the original node was a declaration and we wrote an
                // update mark the declaration as used.
                if ( t.write.contains(decl) ) {
                    if ( const auto* node = cfg.graph().getNode(decl->identity()) )
                        ++uses[*node];
                }

                // Else filter by nodes reading the decl.
                if ( ! t.read.contains(decl) )
                    continue;

                // If an update is read and in the `in` set of a node it is used.
                auto it = std::ranges::find_if(t.in, [&](const auto& in) {
                    const auto& [decl, stmts] = in;
                    return stmts.contains(stmt);
                });
                if ( it != t.in.end() )
                    ++uses[n];
            }
        }
    }

    std::vector<Node*> result;
    for ( const auto& [n, uses] : uses ) {
        if ( uses > 0 )
            continue;

        if ( dataflow.at(n).keep )
            continue;

        result.push_back(n.value());
    }

    return result;
}

std::unordered_set<Node*> FunctionBodyVisitor::unreachableNodes(const detail::cfg::CFG& cfg) const {
    std::unordered_set<Node*> result;
    for ( const auto& [id, n] : cfg.graph().nodes() ) {
        if ( n.value() && ! n->isA<detail::cfg::MetaNode>() && cfg.graph().neighborsUpstream(id).empty() )
            result.insert(n.value());
    }

    return result;
}

void detail::optimizer::optimize(Builder* builder, ASTRoot* root) {
    util::timing::Collector _("hilti/compiler/optimizer");

    if ( logger().isEnabled(logging::debug::CfgInitial) ) {
        auto v = PrintCfgVisitor(logging::debug::CfgInitial);
        visitor::visit(v, root);
    }

    const auto passes__ = rt::getenv("HILTI_OPTIMIZER_PASSES");
    const auto& passes_ =
        passes__ ? std::optional(util::split(*passes__, ":")) : std::optional<std::vector<std::string>>();
    auto passes = passes_ ? std::optional(std::set<std::string>(passes_->begin(), passes_->end())) :
                            std::optional<std::set<std::string>>();

    if ( ! passes || passes->contains("feature_requirements") ) {
        // The `FeatureRequirementsVisitor` enables or disables code
        // paths and needs to be run before all other passes since
        // it needs to see the code before any optimization edits.
        FeatureRequirementsVisitor v(builder, hilti::logging::debug::Optimizer);
        v.collect(root);
        v.transform(root);
    }

    CollectUsesPass collect_uses{};
    const auto& op_uses = collect_uses.collect(root);

    using PassCreator = std::unique_ptr<OptimizerVisitor> (*)(Builder* builder, const OperatorUses* op_uses);
    using Phase = size_t;

    const std::map<std::string, std::pair<PassCreator, Phase>> creators = {
        // Passes which mainly edit out code generation artifacts run in the first phase.
        {"constant_folding",
         {[](Builder* builder, const OperatorUses* op_uses) -> std::unique_ptr<OptimizerVisitor> {
              return std::make_unique<ConstantFoldingVisitor>(builder, hilti::logging::debug::Optimizer, op_uses);
          },
          1}},
        {"functions",
         {[](Builder* builder, const OperatorUses* op_uses) -> std::unique_ptr<OptimizerVisitor> {
              return std::make_unique<FunctionVisitor>(builder, hilti::logging::debug::Optimizer, op_uses);
          },
          1}},
        {"members",
         {[](Builder* builder, const OperatorUses* op_uses) -> std::unique_ptr<OptimizerVisitor> {
              return std::make_unique<MemberVisitor>(builder, hilti::logging::debug::Optimizer, op_uses);
          },
          1}},
        {"types",
         {[](Builder* builder, const OperatorUses* op_uses) -> std::unique_ptr<OptimizerVisitor> {
              return std::make_unique<TypeVisitor>(builder, hilti::logging::debug::Optimizer, op_uses);
          },
          1}},

        // Passes which more closely inspect the generated code or which are more general run in the second phase.
        {"remove_unused_params",
         {[](Builder* builder, const OperatorUses* op_uses) -> std::unique_ptr<OptimizerVisitor> {
              return std::make_unique<FunctionParamVisitor>(builder, hilti::logging::debug::Optimizer, op_uses);
          },
          2}},
        {"cfg",
         {[](Builder* builder, const OperatorUses* op_uses) -> std::unique_ptr<OptimizerVisitor> {
              return std::make_unique<FunctionBodyVisitor>(builder, hilti::logging::debug::Optimizer);
          },
          2}},
        {"constant_propagation",
         {[](Builder* builder, const OperatorUses* op_uses) -> std::unique_ptr<OptimizerVisitor> {
              return std::make_unique<ConstantPropagationVisitor>(builder, hilti::logging::debug::Optimizer);
          },
          2}},
    };

    // TODO(bbannier): Control-flow based optimizations are not ready for
    // prime-time yet and behind a feature guard.
    bool has_cfg = rt::getenv("HILTI_OPTIMIZER_ENABLE_CFG") == "1";
    auto uses_cfg = std::unordered_set<std::string>{"cfg", "constant_propagation"};

    // If no user-specified passes are given enable all of them.
    if ( ! passes ) {
        passes = std::set<std::string>();
        for ( const auto& [pass, _] : creators )
            if ( ! uses_cfg.contains(pass) )
                passes->insert(pass);

        if ( has_cfg ) {
            for ( const auto& pass : uses_cfg )
                passes->insert(pass);
        }
    }

    Phase max_phase{};
    for ( const auto& [_, x] : creators )
        max_phase = std::max(x.second, max_phase);

    size_t round = 0;

    // Run the phases in order in a loop until we reach a fixpoint.
    while ( true ) {
        bool modified = false;

        // Run the phases in order.
        for ( Phase phase = 0; phase <= max_phase; ++phase ) {
            // Run all passes in a phase until we reach a fixpoint for the phase.
            while ( true ) {
                modified = false;

                // Filter out passes to run in this phase.
                // NOTE: We do not use `util::transform` here to guarantee a consistent order of the visitors.
                std::vector<std::unique_ptr<OptimizerVisitor>> vs;
                vs.reserve(passes->size());
                for ( const auto& pass : *passes ) {
                    if ( creators.contains(pass) ) {
                        auto&& [create, phase_] = creators.at(pass);

                        if ( phase_ != phase )
                            continue;

                        vs.push_back(create(builder, &op_uses));
                    }
                }

                for ( auto& v : vs ) {
                    HILTI_DEBUG(logging::debug::OptimizerCollect,
                                util::fmt("processing AST, round=%d, phase = %d", round, phase));
                    v->collect(root);
                    modified = v->pruneUses(root) || modified;
                    modified = v->pruneDecls(root) || modified;
                };

                if ( ! modified )
                    break;

                ++round;
            }

            // Clean up simplified code with peephole optimizer.
            while ( true ) {
                auto v = PeepholeOptimizer(builder, hilti::logging::debug::Optimizer);
                visitor::visit(v, root);
                if ( ! v.isModified() )
                    break;
            }
        }

        if ( ! modified )
            break;
    }

    if ( logger().isEnabled(logging::debug::CfgFinal) ) {
        auto v = PrintCfgVisitor(logging::debug::CfgFinal);
        visitor::visit(v, root);
    }

    // Clear cached information which might become outdated due to edits.
    auto v = hilti::visitor::PreOrder();
    for ( auto* n : hilti::visitor::range(v, root, {}) )
        n->clearScope();
}

} // namespace hilti
