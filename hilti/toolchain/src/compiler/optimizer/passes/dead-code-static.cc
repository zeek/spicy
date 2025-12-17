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
using namespace hilti::detail::optimizer;

namespace {

struct Collector : public optimizer::visitor::Collector {
    using optimizer::visitor::Collector::Collector;

    // Map tracking whether a function/type/member ID is used in the code.
    std::map<ID, bool> used;

    // Lookup table for ID -> {feature name -> required}.
    std::map<ID, std::map<std::string, bool>> features;

    // Records type and use of a function.
    struct FunctionUsage {
        bool hook = false;
        bool defined = false;
        bool referenced = false;
    };

    std::map<ID, FunctionUsage> function_usage;

    void done() override {
        if ( ! logger().isEnabled(logging::debug::OptimizerPasses) )
            return;

        HILTI_DEBUG(logging::debug::OptimizerPasses, "IDs:");
        for ( const auto& [id, used] : used )
            HILTI_DEBUG(logging::debug::OptimizerPasses, util::fmt("    %s: used=%d", id, used));

        HILTI_DEBUG(logging::debug::OptimizerPasses, "    Feature status:");
        for ( const auto& [id, features] : features ) {
            std::stringstream ss;
            ss << "        " << id << ':';
            for ( const auto& [feature, enabled] : features )
                ss << util::fmt(" %s=%d", feature, enabled);
            HILTI_DEBUG(logging::debug::OptimizerPasses, ss.str());
        }

        HILTI_DEBUG(logging::debug::OptimizerPasses, "Functions:");
        for ( const auto& [id, uses] : function_usage )
            HILTI_DEBUG(logging::debug::OptimizerPasses, util::fmt("    %s: defined=%d referenced=%d hook=%d", id,
                                                                   uses.defined, uses.referenced, uses.hook));
    }

    void run(Node* node = nullptr) override {
        // Helper to compute the total number of collected features over all types.
        auto num_features = [&]() {
            return std::accumulate(features.begin(), features.end(), 0U,
                                   [](auto acc, auto&& f) { return acc + f.second.size(); });
        };

        init();

        // Whether a function can be elided depends on which features are
        // active. Since we discover features as we visit the AST (which likely
        // contains multiple modules), we need to iterate until we have
        // collected all features.
        while ( true ) {
            const auto num_features_before = num_features();
            hilti::visitor::visit(*this, node ? node : context()->root());
            const auto num_features_after = num_features();

            // We have seen everything since no new features were found.
            if ( num_features_before == num_features_after )
                break;
        }

        done();
    }

    void operator()(declaration::Field* n) final {
        if ( const auto& type_id = n->type()->type()->typeID() )
            used[type_id] = true;

        const auto& parent_type = n->linkedType(context());
        assert(parent_type);

        auto member_id = ID(parent_type->typeID(), n->id());
        used.insert({member_id, false});

        if ( const auto* ftype = n->type()->type()->tryAs<type::Function>() ) {
            auto& usage = function_usage[n->fullyQualifiedID()];

            // If the member declaration is marked `&always-emit` mark it as implemented.
            if ( n->attributes()->find(hilti::attribute::kind::AlwaysEmit) )
                usage.defined = true;

            // If the member declaration includes a body mark it as implemented.
            if ( const auto* function = n->inlineFunction(); function && function->body() )
                usage.defined = true;

            if ( ftype->flavor() == type::function::Flavor::Hook )
                usage.hook = true;

            if ( const auto* parent_decl = parent_type->typeDeclaration() ) {
                // If the unit is wrapped in a type with a `&cxxname` attribute its
                // members are defined in C++ as well.
                if ( parent_decl->attributes()->find(hilti::attribute::kind::Cxxname) )
                    usage.defined = true;

                for ( const auto& attr : n->attributes()->findAll(hilti::attribute::kind::NeededByFeature) ) {
                    auto feature = *attr->valueAsString();
                    // If no feature constants were collected yet, reschedule
                    // us for the next collection pass.
                    //
                    // NOTE: If we emit a `&needed-by-feature` attribute we
                    // also always emit a matching feature constant, so
                    // eventually at this point we will see at least one
                    // feature constant.
                    auto it = features.find(parent_decl->type()->type()->typeID());
                    if ( it == features.end() || ! it->second.contains(feature) )
                        // This feature requirement has not yet been collected.
                        continue;

                    usage.referenced |= it->second.at(feature);
                }
            }
        }
    }

    void operator()(declaration::Function* n) final {
        // Record the function if not already known.
        auto& usage = function_usage[n->functionID(context())];

        const auto& function = n->function();

        // If the declaration contains a function with a body mark the function as defined.
        if ( function->body() )
            usage.defined = true;

        // If the declaration has a `&cxxname` it is defined in C++.
        else if ( function->attributes()->find(hilti::attribute::kind::Cxxname) )
            usage.defined = true;

        // If the member declaration is marked `&always-emit` mark it as referenced.
        if ( function->attributes()->find(hilti::attribute::kind::AlwaysEmit) )
            usage.referenced = true;

        // If the function is public mark is as referenced.
        if ( n->linkage() == declaration::Linkage::Public )
            usage.referenced = true;

        const auto* decl = n->linkedDeclaration(context());

        if ( decl ) {
            // As this type is referenced by a function declaration it is used.
            used[decl->fullyQualifiedID()] = true;

            // For implementation of methods check whether the method
            // should only be emitted when certain features are active.
            for ( const auto& requirement : function->attributes()->findAll(hilti::attribute::kind::NeededByFeature) ) {
                const auto& requirement_ = requirement->valueAsString();
                const auto& feature = *requirement_;

                // If no feature constants were collected yet, reschedule us for the next collection pass.
                //
                // NOTE: If we emit a `&needed-by-feature` attribute we also always emit a matching feature
                // constant, so eventually at this point we will see at least one feature constant.
                auto it = features.find(decl->fullyQualifiedID());
                if ( it == features.end() || ! it->second.contains(feature) )
                    // This feature requirement has not yet been collected.
                    continue;

                // Mark the function as referenced if it is needed by an active feature.
                usage.referenced |= it->second.at(feature);
            }
        }

        if ( function->ftype()->flavor() == type::function::Flavor::Hook )
            usage.hook = true;

        switch ( function->ftype()->callingConvention() ) {
            case type::function::CallingConvention::ExternNoSuspend:
            case type::function::CallingConvention::Extern: {
                // If the declaration is `extern` and the unit is `public`, the function
                // is part of an externally visible API and potentially used elsewhere.
                if ( decl )
                    usage.referenced |= (decl->linkage() == declaration::Linkage::Public);
                else
                    usage.referenced = true;

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
                usage.referenced = true;
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
                    usage.referenced = false;
                    usage.hook = false;
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
        used.insert({type_id, n->linkage() == declaration::Linkage::Public});
    }

    void operator()(expression::Member* n) final {
        const auto* op = n->parent()->tryAs<expression::ResolvedOperator>();
        if ( ! op )
            return;

        const auto* struct_ = op->op0()->type()->innermostType()->type()->tryAs<type::Struct>();
        if ( ! struct_ )
            return;

        auto type_id = struct_->typeID();
        assert(type_id);

        auto member_id = ID(type_id, n->id());
        used[member_id] = true;
    }

    void operator()(expression::Name* n) final {
        if ( const auto& type_id = n->type()->type()->typeID() )
            used[type_id] = true;

        if ( const auto* decl = n->resolvedDeclaration(); decl && decl->isA<declaration::Field>() )
            used[n->id()] = true;
    }

    void operator()(expression::Type_* n) final {
        if ( const auto type_id = n->typeValue()->type()->typeID() )
            used[type_id] = true;
    }

    void operator()(operator_::struct_::MemberCall* n) final {
        const auto* struct_ = n->op0()->type()->type()->tryAs<type::Struct>();
        assert(struct_);

        const auto& member = n->op1()->tryAs<expression::Member>();
        assert(member);

        const auto* field = struct_->field(member->id());
        assert(field);

        const auto& function_id = field->fullyQualifiedID();
        assert(function_id);

        function_usage[function_id].referenced = true;
    }

    void operator()(operator_::function::Call* n) final {
        const auto* decl = n->op0()->as<expression::Name>()->resolvedDeclaration();
        assert(decl);

        const auto& function_id = decl->fullyQualifiedID();
        assert(function_id);

        function_usage[function_id].referenced = true;
    }

    void operator()(declaration::Constant* n) final {
        const auto& id_feature = hilti::detail::Optimizer::idFeatureFromConstant(n->id());
        if ( ! id_feature )
            return;

        const auto& [type_id, feature] = *id_feature;
        features[type_id][feature] = n->value()->as<expression::Ctor>()->ctor()->as<ctor::Bool>()->value();
    }

    void operator()(type::Name* n) final {
        const auto& type_id = n->resolvedType()->typeID();
        assert(type_id);
        used[type_id] = true;
    }

    void operator()(UnqualifiedType* n) final {
        if ( n->parent(2)->isA<declaration::Type>() )
            return;

        if ( const auto& type_id = n->typeID() )
            used[type_id] = true;
    }
};

struct Mutator : public optimizer::visitor::Mutator {
    Mutator(Optimizer* optimizer, const Collector* collector)
        : optimizer::visitor::Mutator(optimizer), collector(collector) {}

    const Collector* collector = nullptr;

    std::optional<bool> tryAsBoolLiteral(const Expression* x) {
        if ( const auto* expression = x->tryAs<expression::Ctor>() ) {
            const auto* ctor = expression->ctor();

            if ( const auto* x = ctor->tryAs<ctor::Coerced>() )
                ctor = x->coercedCtor();

            if ( const auto* bool_ = ctor->tryAs<ctor::Bool>() )
                return {bool_->value()};
        }

        return {};
    }

    void operator()(declaration::Field* n) final {
        const auto& parent_type = n->linkedType(context());
        assert(parent_type);

        auto member_id = ID(parent_type->typeID(), n->id());
        bool remove = (! collector->used.at(member_id));

        // Check whether the field depends on an active feature in which case
        // we do not remove the field.
        if ( auto parent_id = parent_type->typeID(); collector->features.contains(parent_id) ) {
            const auto& features_ = collector->features.at(parent_id);

            for ( const auto& dependent_feature_ : n->attributes()->findAll(hilti::attribute::kind::NeededByFeature) ) {
                auto dependent_feature = *dependent_feature_->valueAsString();

                // The feature flag is known and the feature is active.
                if ( features_.contains(dependent_feature) && features_.at(dependent_feature) )
                    remove = false;
            }
        }

        // We never remove members marked `&always-emit`.
        if ( n->attributes()->find(hilti::attribute::kind::AlwaysEmit) )
            remove = false;

        // We only remove members marked `&internal`.
        if ( ! n->attributes()->find(hilti::attribute::kind::Internal) )
            remove = false;

        if ( remove ) {
            removeNode(n, "removing unused member");
            return;
        }

        if ( n->type()->type()->tryAs<type::Function>() ) {
            const auto& usage = collector->function_usage.at(n->fullyQualifiedID());

            // Remove function methods without implementation.
            if ( ! usage.defined && ! usage.referenced ) {
                removeNode(n, "removing declaration for unused method");
                return;
            }
        }
    }

    void operator()(declaration::Function* n) final {
        const auto& usage = collector->function_usage.at(n->functionID(context()));

        if ( usage.hook && ! usage.defined )
            removeNode(n, "removing declaration for unused hook function");
        else if ( ! usage.hook && ! usage.referenced )
            removeNode(n, "removing declaration for unused function");
    }

    void operator()(expression::Ternary* n) final {
        auto bool_ = tryAsBoolLiteral(n->condition());
        if ( ! bool_ )
            return;

        if ( *bool_ )
            replaceNode(n, n->true_(), "replacing ternary with true branch");
        else
            replaceNode(n, n->false_(), "replacing ternary with false branch");
    }

    void operator()(operator_::struct_::MemberCall* n) final {
        const auto* struct_ = n->op0()->type()->type()->tryAs<type::Struct>();
        assert(struct_);

        const auto& member = n->op1()->tryAs<expression::Member>();
        assert(member);

        const auto* field = struct_->field(member->id());
        assert(field);

        const auto& function_id = field->fullyQualifiedID();
        assert(function_id);

        if ( const auto& usage = collector->function_usage.at(function_id); ! usage.defined )
            // Replace call node referencing unimplemented member function with default value.
            replaceNode(n, builder()->expressionCtor(builder()->ctorDefault(n->result()->type())),
                        "replacing call to unimplemented method with default value");
    }

    void operator()(declaration::Type* n) final {
        // We currently only handle type declarations for struct types or enum types.
        //
        // TODO(bbannier): Handle type aliases.
        if ( const auto& type = n->type(); ! (type->type()->isA<type::Struct>() || type->type()->isA<type::Enum>()) )
            return;

        const auto& type_id = n->typeID();
        if ( ! type_id )
            return;

        if ( ! collector->used.at(type_id) )
            removeNode(n, "removing unused type");
    }

    void operator()(operator_::function::Call* n) final {
        auto* decl = n->op0()->as<expression::Name>()->resolvedDeclaration();
        assert(decl);

        const auto& function_id = decl->fullyQualifiedID();
        assert(function_id);

        const auto& function = collector->function_usage.at(function_id);

        // Replace call node referencing unimplemented hook with default value.
        if ( function.hook && ! function.defined ) {
            auto* new_ = builder()->expressionCtor(
                builder()->ctorDefault(decl->as<declaration::Function>()->function()->ftype()->result()->type()));
            replaceNode(n, new_, "replacing call to unimplemented function with default value");
        }
    }

    void operator()(statement::If* n) final {
        if ( n->init() )
            // Leave this alone for now as it may have side effects.
            return;

        auto bool_ = tryAsBoolLiteral(n->condition());
        if ( ! bool_ )
            return;

        if ( bool_.value() )
            replaceNode(n, n->true_()->removeFromParent(), "replacing if statement with true block");
        else if ( n->false_() )
            replaceNode(n, n->false_()->removeFromParent(), "replacing if statement with else block");
        else
            removeNode(n, "removing if statement with always-false condition");
    }

    void operator()(statement::While* n) final {
        if ( n->init() )
            // Leave this alone for now as it may have side effects.
            return;

        const auto* condition = n->condition();
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
                replaceNode(n, n->else_()->removeFromParent(), "replacing while loop with its else block");
            else {
                recordChange(n, "removing while loop with false condition");
                n->parent()->removeChild(n);
            }
        }
    }

    void operator()(statement::Expression* n) final {
        // Remove expression statements without side effects.
        if ( const auto* expr = n->expression(); expr->isConstant() && expr->isA<expression::Ctor>() )
            removeNode(n, "removing unused expression result");
    }
};

bool run(Optimizer* optimizer) {
    Collector collector(optimizer);
    collector.run();

    return Mutator(optimizer, &collector).run();
}

optimizer::RegisterPass constant_folder({.id = PassID::DeadCodeStatic,
                                         .guarantees = Guarantees::ConstantsFolded,
                                         .run = run});

} // namespace
