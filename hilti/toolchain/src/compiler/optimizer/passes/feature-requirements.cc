// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <hilti/ast/builder/builder.h>
#include <hilti/ast/scope-lookup.h>
#include <hilti/base/logger.h>
#include <hilti/compiler/detail/optimizer/pass.h>

using namespace hilti;
using namespace hilti::detail;
using namespace hilti::detail::optimizer;

namespace {

// This visitor collects requirement attributes in the AST, determining which
// ones are in use across code.
struct Collector : public optimizer::visitor::Collector {
    using optimizer::visitor::Collector::Collector;

    // Lookup table for feature name -> required.
    using Features = std::map<std::string, bool>;

    // Lookup table for typename -> features.
    std::map<ID, Features> features;

    void done() final {
        if ( ! logger().isEnabled(logging::debug::OptimizerPasses) )
            return;

        HILTI_DEBUG(logging::debug::OptimizerPasses, "Feature requirements:");

        for ( const auto& [id, features] : features ) {
            std::stringstream ss;
            ss << "    " << id << ':';
            for ( const auto& [feature, enabled] : features )
                ss << util::fmt(" %s=%d", feature, enabled);

            HILTI_DEBUG(logging::debug::OptimizerPasses, ss.str());
        }
    }

    // Helper function to compute all feature flags participating in a
    // condition. Feature flags are always combined with logical `or`.
    static void featureFlagsFromCondition(Expression* condition, std::map<ID, std::set<std::string>>* result) {
        if ( const auto* rid = condition->tryAs<expression::Name>() ) {
            if ( auto id_feature = Optimizer::idFeatureFromConstant(rid->id()) )
                (*result)[std::move(id_feature->first)].insert(std::move(id_feature->second));
        }

        // If we did not find a feature constant in the conditional, we
        // could also be dealing with a `OR` of feature constants.
        else if ( const auto* or_ = condition->tryAs<expression::LogicalOr>() ) {
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

                featureFlagsFromCondition(condition, &result);
            }

            else if ( const auto& ternary = parent->tryAs<expression::Ternary>() )
                featureFlagsFromCondition(ternary->condition(), &result);
        }

        return result;
    }

    void operator()(declaration::Constant* n) final {
        const auto& id_feature = hilti::detail::Optimizer::idFeatureFromConstant(n->id());
        if ( ! id_feature )
            return;

        const auto& [type_id, feature] = *id_feature;

        // Record the feature as unused for the type if it was not already recorded.
        features[type_id].insert({feature, false});
    }

    void operator()(operator_::function::Call* n) final {
        // Collect parameter requirements from the declaration of the called function.
        std::vector<std::set<std::string>> requirements;

        const auto* rid = n->op0()->tryAs<expression::Name>();
        if ( ! rid )
            return;

        const auto* decl = rid->resolvedDeclaration();
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
            const auto* type = arg->type()->innermostType();

            // Ignore arguments types without type ID (e.g., builtin types).
            const auto& type_id = type->type()->typeID();
            if ( ! type_id ) {
                ++i;
                continue;
            }

            for ( const auto& requirement : requirements[i] ) {
                if ( ! ignored_features.contains(type_id) || ! ignored_features.at(type_id).contains(requirement) )
                    // Enable the required feature.
                    features[type_id][requirement] = true;
            }

            ++i;
        }
    }

    void operator()(operator_::struct_::MemberCall* n) final {
        const auto* type = n->op0()->type();
        while ( type->type()->isReferenceType() )
            type = type->type()->dereferencedType();

        const auto* const struct_ = type->type()->tryAs<type::Struct>();
        if ( ! struct_ )
            return;

        const auto& member = n->op1()->as<expression::Member>();

        const auto* const field = struct_->field(member->id());
        if ( ! field )
            return;

        const auto ignored_features = conditionalFeatures(n);

        // Check if access to the field has type requirements.
        if ( auto type_id = type->type()->typeID() )
            for ( const auto& requirement : field->attributes()->findAll(hilti::attribute::kind::NeededByFeature) ) {
                const auto feature = *requirement->valueAsString();
                if ( ! ignored_features.contains(type_id) || ! ignored_features.at(type_id).contains(feature) )
                    // Enable the required feature.
                    features[type_id][*requirement->valueAsString()] = true;
            }

        // Check if call imposes requirements on any of the types of the arguments.
        const auto& op = static_cast<const struct_::MemberCall&>(n->operator_());
        assert(op.declaration());
        const auto* ftype = op.declaration()->type()->type()->as<type::Function>();

        const auto parameters = ftype->parameters();
        if ( parameters.empty() )
            return;

        const auto& args = n->op2()->as<expression::Ctor>()->ctor()->as<ctor::Tuple>()->value();

        for ( size_t i = 0; i < parameters.size(); ++i ) {
            // Since the declaration might use `any` types, get the
            // type of the parameter from the passed argument.

            // Instead of applying the type requirement only to the
            // potentially unref'd passed value's type, we also apply
            // it to the element type of list args. Since this
            // optimizer pass removes code worst case this could lead
            // to us optimizing less.
            const auto* const type = args[i]->type()->innermostType();
            const auto& param = parameters[i];

            if ( auto type_id = type->type()->typeID() )
                for ( const auto& requirement :
                      param->attributes()->findAll(hilti::attribute::kind::RequiresTypeFeature) ) {
                    const auto feature = *requirement->valueAsString();
                    if ( ! ignored_features.contains(type_id) || ! ignored_features.at(type_id).contains(feature) )
                        // Enable the required feature.
                        features[type_id][feature] = true;
                }
        }
    }

    // Helper handling both const and non-const struct member access.
    void handleMemberAccess(expression::ResolvedOperator* x) {
        const auto* type_ = x->op0()->type();
        while ( type_->type()->isReferenceType() )
            type_ = type_->type()->dereferencedType();

        auto type_id = type_->type()->typeID();
        if ( ! type_id )
            return;

        const auto* member = x->op1()->tryAs<expression::Member>();
        if ( ! member )
            return;

        auto lookup = scope::lookupID<declaration::Type>(type_id, x, "type");
        if ( ! lookup )
            return;

        const auto* type = lookup->first->template as<declaration::Type>();
        const auto* struct_ = type->type()->type()->template tryAs<type::Struct>();
        if ( ! struct_ )
            return;

        const auto* field = struct_->field(member->id());
        if ( ! field )
            return;

        const auto ignored_features = conditionalFeatures(x);

        for ( const auto& requirement : field->attributes()->findAll(hilti::attribute::kind::NeededByFeature) ) {
            const auto feature = *requirement->valueAsString();

            // Enable the required feature if it is not ignored here.
            if ( ! ignored_features.contains(type_id) || ! ignored_features.at(type_id).contains(feature) )
                features[type_id][feature] = true;
        }
    }

    void operator()(operator_::struct_::MemberConst* n) final { handleMemberAccess(n); }
    void operator()(operator_::struct_::MemberNonConst* n) final { handleMemberAccess(n); }

    void operator()(declaration::Type* n) final {
        // Collect feature requirements associated with type.
        for ( const auto& requirement : n->attributes()->findAll(hilti::attribute::kind::RequiresTypeFeature) )
            features[n->typeID()][*requirement->valueAsString()] = true;
    }
};

struct Mutator : public optimizer::visitor::Mutator {
    Mutator(Optimizer* optimizer, const Collector* collector)
        : optimizer::visitor::Mutator(optimizer), collector(collector) {}

    const Collector* collector = nullptr;

    void operator()(declaration::Constant* n) final {
        const auto& id_feature = Optimizer::idFeatureFromConstant(n->id());
        if ( ! id_feature )
            return;

        const auto& [type_id, feature] = *id_feature;

        const auto required = collector->features.at(type_id).at(feature);
        const auto value = n->value()->as<expression::Ctor>()->ctor()->as<ctor::Bool>()->value();

        if ( ! required && value ) {
            recordChange(n, util::fmt("disabling feature '%s' of type '%s' since it is not used", feature, type_id));
            n->setValue(context(), builder()->bool_(false));
        }
    }

    void operator()(declaration::Type* n) final {
        if ( ! collector->features.contains(n->fullyQualifiedID()) )
            return;

        // Add type comment documenting enabled features.
        auto meta = n->meta();
        auto comments = meta.comments();

        if ( auto enabled_features = collector->features.at(n->fullyQualifiedID()) |
                                     std::views::filter([](const auto& feature) { return feature.second; });
             ! enabled_features.empty() ) {
            comments.push_back(util::fmt("Type %s supports the following features:", n->id()));
            for ( const auto& feature : enabled_features )
                comments.push_back(util::fmt("    - %s", feature.first));
        }

        meta.setComments(std::move(comments));
        n->setMeta(std::move(meta));

        // No need to record a change here since comments do not affect any semantics.
    }
};

bool run(Optimizer* optimizer) {
    Collector collector(optimizer);
    collector.run();

    return Mutator(optimizer, &collector).run();
}

optimizer::RegisterPass feature_requirements({.id = PassID::FeatureRequirements,
                                              .one_time = true,
                                              .iterate = false,
                                              .guarantees = Guarantees::Resolved | Guarantees::CFGUnchanged,
                                              .run = run});

} // namespace
