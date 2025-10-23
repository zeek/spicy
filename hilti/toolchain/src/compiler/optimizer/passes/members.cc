// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <hilti/ast/builder/builder.h>
#include <hilti/ast/scope-lookup.h>
#include <hilti/base/logger.h>
#include <hilti/compiler/detail/optimizer/optimizer.h>

using namespace hilti;
using namespace hilti::detail::optimizer;

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

static RegisterPass constant_folder(
    "members", {[](Builder* builder, const OperatorUses* op_uses) -> std::unique_ptr<OptimizerVisitor> {
                    return std::make_unique<MemberVisitor>(builder, hilti::logging::debug::Optimizer, op_uses);
                },
                1});
