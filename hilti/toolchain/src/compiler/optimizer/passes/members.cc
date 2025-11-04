// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <hilti/ast/builder/builder.h>
#include <hilti/ast/scope-lookup.h>
#include <hilti/base/logger.h>
#include <hilti/compiler/detail/optimizer/pass.h>

using namespace hilti;
using namespace hilti::detail;

namespace {

struct Collector : public optimizer::visitor::Collector {
    using optimizer::visitor::Collector::Collector;

    // Map tracking whether a member is used in the code.
    std::map<std::string, bool> used;

    // Map tracking for each type which features are enabled.
    std::map<ID, std::map<std::string, bool>> features;

    void done() final {
        if ( logger().isEnabled(logging::debug::OptimizerDetail) ) {
            HILTI_DEBUG(logging::debug::OptimizerDetail, "members:");

            HILTI_DEBUG(logging::debug::OptimizerDetail, "    feature status:");
            for ( const auto& [id, features] : features ) {
                std::stringstream ss;
                ss << "        " << id << ':';
                for ( const auto& [feature, enabled] : features )
                    ss << util::fmt(" %s=%d", feature, enabled);
                HILTI_DEBUG(logging::debug::OptimizerDetail, ss.str());
            }

            for ( const auto& [id, used] : used )
                HILTI_DEBUG(logging::debug::OptimizerDetail, util::fmt("    %s used=%d", id, used));
        }
    }

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

        // Record the member if it is not yet known.
        used.insert({member_id, false});
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
        used[member_id] = true;
    }

    void operator()(expression::Name* n) final {
        auto* decl = n->resolvedDeclaration();
        if ( ! decl || ! decl->isA<declaration::Field>() )
            return;

        // Record the member as used.
        used[n->id()] = true;
    }

    void operator()(declaration::Constant* n) final {
        // Check whether the feature flag matches the type of the field.
        if ( ! util::startsWith(n->id(), "__feat%") )
            return;

        auto tokens = util::split(n->id(), "%");
        assert(tokens.size() == 3);

        auto type_id = ID(tokens[1]);
        const auto& feature = tokens[2];
        auto is_active = n->value()->as<expression::Ctor>()->ctor()->as<ctor::Bool>()->value();

        type_id = ID(util::replace(type_id, "@@", "::"));
        features[type_id][feature] = is_active;
    }
};

struct Mutator : public optimizer::visitor::Mutator {
    Mutator(Optimizer* optimizer, const Collector* collector)
        : optimizer::visitor::Mutator(optimizer), collector(collector) {}

    const Collector* collector = nullptr;

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

        if ( ! collector->used.at(member_id) ) {
            // Check whether the field depends on an active feature in which case we do not remove the
            // field.
            if ( collector->features.contains(type_id) ) {
                const auto& features_ = collector->features.at(type_id);

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
};

optimizer::Result run(Optimizer* optimizer) {
    Collector collector(optimizer);
    collector.run();

    return Mutator(optimizer, &collector).run();
}

optimizer::RegisterPass members({.name = "members",
                                 .phase = optimizer::Phase::Phase1,
                                 .requires_afterwards = optimizer::Requirements::ScopeBuilder |
                                                        optimizer::Requirements::TypeUnifier,
                                 .run = run});

} // namespace
