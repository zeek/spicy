// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <numeric>

#include <hilti/ast/builder/builder.h>
#include <hilti/ast/ctors/bool.h>
#include <hilti/ast/declarations/constant.h>
#include <hilti/ast/expressions/ctor.h>
#include <hilti/ast/expressions/name.h>
#include <hilti/base/logger.h>
#include <hilti/compiler/detail/optimizer/optimizer.h>
#include <hilti/compiler/detail/optimizer/pass.h>

using namespace hilti;
using namespace hilti::detail;

namespace {

struct Collector : public optimizer::visitor::Collector {
    using optimizer::visitor::Collector::Collector;

    /////  XX from former functions

    struct FunctionUses {
        bool hook = false;
        bool defined = false;
        bool referenced = false;
    };

    // Lookup table for feature name -> required.
    using Features = std::map<std::string, bool>;

    // Lookup table for typename -> features.
    std::map<ID, Features> type_features;

    std::map<ID, FunctionUses> data;

    /////  XX from former members

    // Map tracking whether a member is used in the code.
    std::map<std::string, bool> members_used;

    // Map tracking for each type which features are enabled.
    std::map<ID, std::map<std::string, bool>> members_features;

    //// XX from types
    std::map<ID, bool> types_used;

    // TODO: Do not override run here.
    void run() override {
        // Helper to compute the total number of collected features over all types.
        auto num_features = [&]() {
            return std::accumulate(type_features.begin(), type_features.end(), 0U,
                                   [](auto acc, auto&& f) { return acc + f.second.size(); });
        };

        // Whether a function can be elided depends on which features are active. Since we discover features as we visit
        // the AST (which likely contains multiple modules), we need to iterate until we have collected all features.
        while ( true ) {
            const auto num_features_0 = num_features();

            hilti::visitor::visit(*this, context()->root());

            if ( logger().isEnabled(logging::debug::OptimizerDetail) ) {
                HILTI_DEBUG(logging::debug::OptimizerDetail, "functions:");
                for ( const auto& [id, uses] : data )
                    HILTI_DEBUG(logging::debug::OptimizerDetail,
                                util::fmt("    %s: defined=%d referenced=%d hook=%d", id, uses.defined, uses.referenced,
                                          uses.hook));
            }

            const auto num_features_1 = num_features();

            // We have seen everything since no new features were found.
            if ( num_features_0 == num_features_1 )
                break;
        }
    }

    void done() override {
        if ( logger().isEnabled(logging::debug::OptimizerDetail) ) {
            HILTI_DEBUG(logging::debug::OptimizerDetail, "members:");

            HILTI_DEBUG(logging::debug::OptimizerDetail, "    feature status:");
            for ( const auto& [id, features] : members_features ) {
                std::stringstream ss;
                ss << "        " << id << ':';
                for ( const auto& [feature, enabled] : features )
                    ss << util::fmt(" %s=%d", feature, enabled);
                HILTI_DEBUG(logging::debug::OptimizerDetail, ss.str());
            }

            for ( const auto& [id, used] : members_used )
                HILTI_DEBUG(logging::debug::OptimizerDetail, util::fmt("    %s used=%d", id, used));
        }

        if ( logger().isEnabled(logging::debug::OptimizerDetail) ) {
            HILTI_DEBUG(logging::debug::OptimizerDetail, "types:");
            for ( const auto& [id, used] : types_used )
                HILTI_DEBUG(logging::debug::OptimizerDetail, util::fmt("    %s: used=%d", id, used));
        }
    }

    void operator()(declaration::Field* n) final {
        // From functions
        if ( n->type()->type()->isA<type::Function>() && n->parent()->isA<type::Struct>() ) {
            const auto& function_id = n->fullyQualifiedID();
            assert(function_id);

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
                for ( const auto& requirement : n->attributes()->findAll(hilti::attribute::kind::NeededByFeature) ) {
                    const auto& requirement_ = requirement->valueAsString();
                    const auto& feature = *requirement_;

                    // If no feature constants were collected yet, reschedule us for the next collection pass.
                    //
                    // NOTE: If we emit a `&needed-by-feature` attribute we also always emit a matching feature
                    // constant, so eventually at this point we will see at least one feature constant.
                    if ( type_features.empty() )
                        return;

                    auto it = type_features.find(type->type()->type()->typeID());
                    if ( it == type_features.end() || ! it->second.contains(feature) )
                        // This feature requirement has not yet been collected.
                        continue;

                    function.referenced = function.referenced || it->second.at(feature);
                }
            }
        }

        // From types
        const auto type_idX = n->type()->type()->typeID();

        if ( type_idX )
            // Record this type as used.
            types_used[type_idX] = true;

        // From members
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

        // Record the member if it is not yet known.
        members_used.insert({member_id, false});
    }

    void operator()(declaration::Function* n) final {
        // From types
        if ( auto* const decl = context()->lookup(n->linkedDeclarationIndex()) ) {
            // If this type is referenced by a function declaration it is used.
            types_used[decl->fullyQualifiedID()] = true;
        }

        // From functions
        auto function_id = n->functionID(context());

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
            for ( const auto& requirement : fn->attributes()->findAll(hilti::attribute::kind::NeededByFeature) ) {
                const auto& requirement_ = requirement->valueAsString();
                const auto& feature = *requirement_;

                // If no feature constants were collected yet, reschedule us for the next collection pass.
                //
                // NOTE: If we emit a `&needed-by-feature` attribute we also always emit a matching feature
                // constant, so eventually at this point we will see at least one feature constant.
                if ( type_features.empty() ) {
                    return;
                }

                auto it = type_features.find(decl->fullyQualifiedID());
                if ( it == type_features.end() || ! it->second.contains(feature) ) {
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
                    function.referenced = function.referenced || decl->linkage() == declaration::Linkage::Public;
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

        // Record the type if not already known. If the type is part of an external API record it as used.
        types_used.insert({type_id, n->linkage() == declaration::Linkage::Public});
    }

    void operator()(expression::Member* n) final {
        auto* expr = n->parent()->children()[1]->tryAs<Expression>();
        if ( ! expr )
            return;

        auto* const type = optimizer()->innermostType(expr->type());

        auto* struct_ = type->type()->tryAs<type::Struct>();
        if ( ! struct_ )
            return;

        auto type_id = type->type()->typeID();
        if ( ! type_id )
            return;

        auto member_id = util::join({std::move(type_id), n->id()}, "::");

        // Record the member as used.
        members_used[member_id] = true;
    }

    void operator()(expression::Name* n) final {
        // From members
        auto* decl = n->resolvedDeclaration();
        if ( decl && decl->isA<declaration::Field>() ) {
            // Record the member as used.
            members_used[n->id()] = true;
        }

        // From types
        auto* const type = optimizer()->innermostType(n->type());

        const auto& type_id = type->type()->typeID();

        if ( ! type_id )
            return;

        // Record this type as used.
        types_used[type_id] = true;
    }

    void operator()(expression::Type_* n) final {
        const auto type_id = n->typeValue()->type()->typeID();
        ;

        if ( ! type_id )
            return;

        // Record this type as used.
        types_used[type_id] = true;
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

        auto& function = data[function_id];

        function.referenced = true;
    }

    void operator()(operator_::function::Call* n) final {
        if ( ! n->hasOp0() )
            return;

        auto* decl = n->op0()->as<expression::Name>()->resolvedDeclaration();
        if ( ! decl )
            return;

        const auto& function_id = decl->fullyQualifiedID();
        assert(function_id);

        auto& function = data[function_id];

        function.referenced = true;
    }

    void operator()(declaration::Constant* n) final {
        // From members
        if ( util::startsWith(n->id(), "__feat%") ) {
            auto tokens = util::split(n->id(), "%");
            assert(tokens.size() == 3);

            auto type_id = ID(tokens[1]);
            const auto& feature = tokens[2];
            auto is_active = n->value()->as<expression::Ctor>()->ctor()->as<ctor::Bool>()->value();

            type_id = ID(util::replace(type_id, "@@", "::"));
            members_features[type_id][feature] = is_active;
        }

        // From functions
        std::optional<bool> value;
        if ( auto* ctor = n->value()->tryAs<expression::Ctor>() )
            if ( auto* bool_ = ctor->ctor()->tryAs<ctor::Bool>() )
                value = bool_->value();

        if ( value ) {
            const auto& id = n->id();

            const auto& id_feature = optimizer()->idFeatureFromConstant(n->id());
            if ( ! id_feature )
                return;

            const auto& [type_id, feature] = *id_feature;

            // We only work on feature flags.
            if ( ! optimizer()->isFeatureFlag(id) )
                return;

            type_features[type_id].insert({feature, *value});
        }
    }

    void operator()(type::Name* n) final {
        auto* t = n->resolvedType();
        assert(t);

        if ( const auto& type_id = t->typeID() )
            // Record this type as used.
            types_used[type_id] = true;
    }

    void operator()(UnqualifiedType* n) final {
        if ( n->parent(2)->isA<declaration::Type>() )
            return;

        if ( const auto& type_id = n->typeID() )
            // Record this type as used.
            types_used[type_id] = true;
    }
};

struct Mutator : public optimizer::visitor::Mutator {
    Mutator(Optimizer* optimizer, const Collector* collector)
        : optimizer::visitor::Mutator(optimizer), collector(collector) {}

    const Collector* collector = nullptr;

    std::optional<bool> tryAsBoolLiteral(Expression* x) {
        if ( auto* expression = x->tryAs<expression::Ctor>() ) {
            auto* ctor = expression->ctor();

            if ( auto* x = ctor->tryAs<ctor::Coerced>() )
                ctor = x->coercedCtor();

            if ( auto* bool_ = ctor->tryAs<ctor::Bool>() )
                return {bool_->value()};
        }

        return {};
    }

    void operator()(declaration::Field* n) final {
        // From members
        auto type_id = n->parent()->as<UnqualifiedType>()->typeID();
        if ( type_id ) {
            // We never remove member marked `&always-emit`.
            if ( n->attributes()->find(hilti::attribute::kind::AlwaysEmit) )
                goto next;

            // We only remove member marked `&internal`.
            if ( ! n->attributes()->find(hilti::attribute::kind::Internal) )
                goto next;

            auto member_id = util::join({type_id, n->id()}, "::");

            if ( ! collector->members_used.at(member_id) ) {
                // Check whether the field depends on an active feature in which case we do not remove the
                // field.
                if ( collector->members_features.contains(type_id) ) {
                    const auto& features_ = collector->members_features.at(type_id);

                    auto dependent_features =
                        hilti::node::transform(n->attributes()->findAll(hilti::attribute::kind::NeededByFeature),
                                               [](const auto& attr) { return *attr->valueAsString(); });

                    for ( const auto& dependent_feature_ :
                          n->attributes()->findAll(hilti::attribute::kind::NeededByFeature) ) {
                        auto dependent_feature = *dependent_feature_->valueAsString();

                        // The feature flag is known and the feature is active.
                        if ( features_.contains(dependent_feature) && features_.at(dependent_feature) )
                            goto next; // Use `return` instead of `break` here to break out of `switch`.
                    }
                }

                removeNode(n, "removing unused member");
                return;
            }
        }

    next:
        // From functions
        if ( ! n->type()->type()->isA<type::Function>() )
            return;

        if ( ! n->parent()->isA<type::Struct>() )
            return;

        const auto& function_id = n->fullyQualifiedID();
        assert(function_id);

        const auto& function = collector->data.at(function_id);
        // Remove function methods without implementation.
        if ( ! function.defined && ! function.referenced ) {
            HILTI_DEBUG(logging::debug::Optimizer, util::fmt("removing field for unused method %s", function_id));
            removeNode(n);
            return;
        }
    }

    void operator()(declaration::Function* n) final {
        auto function_id = n->functionID(context());

        const auto& function = collector->data.at(function_id);

        if ( function.hook && ! function.defined ) {
            removeNode(n, "removing declaration for unused hook function");
            return;
        }

        if ( ! function.hook && ! function.referenced ) {
            removeNode(n, "removing declaration for unused function");
            return;
        }
    }

    void operator()(expression::Ternary* n) final {
        auto bool_ = tryAsBoolLiteral(n->condition());
        if ( ! bool_ )
            return;

        if ( *bool_ )
            replaceNode(n, n->true_());
        else
            replaceNode(n, n->false_());
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

        const auto& function = collector->data.at(function_id);

        // Replace call node referencing unimplemented member function with default value.
        if ( ! function.defined ) {
            if ( n->op0()->type()->type()->isA<type::Struct>() )
                replaceNode(n, builder()->expressionCtor(builder()->ctorDefault(n->result()->type())),
                            "replacing call to unimplemented method with default value");
            return;
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

        if ( ! collector->types_used.at(type_id) ) {
            removeNode(n, "removing unused type");
            return;
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

        const auto& function = collector->data.at(function_id);

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
    }
    void operator()(statement::If* n) final {
        auto bool_ = tryAsBoolLiteral(n->condition());
        if ( ! bool_ )
            return;

        if ( auto* else_ = n->false_() ) {
            if ( ! bool_.value() )
                replaceNode(n, else_);
            else {
                auto* init = n->init();
                auto* condition = n->condition();
                auto* true_ = n->true_();

                // Unlink first so that we don't recreate the nodes (which
                // would require new resolving).
                if ( init )
                    init->removeFromParent();

                if ( condition )
                    condition->removeFromParent();

                if ( true_ )
                    true_->removeFromParent();

                replaceNode(n, builder()->statementIf(init, condition, true_, nullptr));
            }
        }
        else {
            if ( ! bool_.value() )
                removeNode(n);
            else
                replaceNode(n, n->true_());
        }
    }

    void operator()(statement::While* n) final {
        auto* condition = n->condition();
        if ( ! condition )
            return;

        auto bool_ = tryAsBoolLiteral(condition);
        if ( ! bool_ )
            return;

        // If the `while` condition is true we never run the `else` block.
        if ( *bool_ && n->else_() ) {
            recordChange(n, "removing else block of while loop with true condition");
            n->removeElse(context());
        }

        // If the `while` condition is false we never enter the loop, and
        // run either the `else` block if it is present or nothing.
        else if ( ! *bool_ ) {
            if ( n->else_() )
                replaceNode(n, n->else_(), "replacing while loop with its else block");
            else {
                recordChange(n, "removing while loop with false condition");
                n->parent()->removeChild(n->as<Node>());
            }
        }
    }
};

optimizer::Result run(Optimizer* optimizer) {
    Collector collector(optimizer);
    collector.run();

    return Mutator(optimizer, &collector).run();
}

optimizer::RegisterPass constant_folder({.name = "dead-code-static",
                                         .order = 10,
                                         .requires_afterwards = optimizer::Requirements::ScopeBuilder |
                                                                optimizer::Requirements::TypeUnifier |
                                                                optimizer::Requirements::Coercer |
                                                                optimizer::Requirements::CFG,
                                         .run = run});

} // namespace
