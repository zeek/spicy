// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include "hilti/compiler/detail/optimizer/optimizer.h"

#include <memory>
#include <optional>
#include <string>
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

detail::optimizer::PassRegistry* detail::optimizer::getPassRegistry() {
    static detail::optimizer::PassRegistry registry;
    return &registry;
}

// Helper function to extract innermost type, removing any wrapping in reference or container types.
QualifiedType* detail::optimizer::innermostType(QualifiedType* type) {
    if ( type->type()->isReferenceType() )
        return innermostType(type->type()->dereferencedType());

    if ( type->type()->iteratorType() )
        return innermostType(type->type()->elementType());

    return type;
}

// Helper to extract `(ID, feature)` from a feature constant.
std::optional<std::pair<ID, std::string>> detail::optimizer::idFeatureFromConstant(const ID& feature_constant) {
    const auto& id = feature_constant.local();

    if ( ! isFeatureFlag(id) )
        return {};

    const auto& tokens = util::split(id, "%");
    assert(tokens.size() == 3);

    auto type_id = ID(util::replace(tokens[1], "@@", "::"));
    const auto& feature = tokens[2];

    return {{type_id, feature}};
};

// Collects uses of resolved operators
struct CollectUsesPass : public hilti::visitor::PreOrder {
    detail::optimizer::OperatorUses result;

    detail::optimizer::OperatorUses collect(Node* node) {
        visitor::visit(*this, node);
        return result;
    }

    void operator()(expression::ResolvedOperator* node) override { result[&node->operator_()].push_back(node); }
};

bool detail::optimizer::optimize(Builder* builder, ASTRoot* root, bool first) {
    util::timing::Collector _("hilti/compiler/optimizer");

    const auto& creators = getPassRegistry()->creators();

    const auto passes__ = rt::getenv("HILTI_OPTIMIZER_PASSES");
    const auto& passes_ = static_cast<bool>(passes__) ? std::optional(util::split(*passes__, ":")) :
                                                        std::optional<std::vector<std::string>>();
    auto passes = static_cast<bool>(passes_) ? std::optional(std::set<std::string>(passes_->begin(), passes_->end())) :
                                               std::optional<std::set<std::string>>();

    if ( (! static_cast<bool>(passes) || passes->contains("feature_requirements")) && first ) {
        // The `FeatureRequirementsVisitor` enables or disables code
        // paths and needs to be run before all other passes since
        // it needs to see the code before any optimization edits.
        const auto& creator_feature_requirements_visitor = creators.at("feature-requirements");
        auto v = (creator_feature_requirements_visitor.first)(builder, nullptr);
        v->collect(root);
        v->transform(root);
    }

    CollectUsesPass collect_uses{};
    auto op_uses = collect_uses.collect(root);

    // Control-flow based optimizations are behind
    // a feature guard which defaults to ON.
    auto flag = rt::getenv("HILTI_OPTIMIZER_ENABLE_CFG");
    bool has_cfg = (! static_cast<bool>(flag) || *flag == "1");
    auto uses_cfg = std::unordered_set<std::string>{"cfg", "constant_propagation"};

    // If no user-specified passes are given enable all of them.
    if ( ! static_cast<bool>(passes) ) {
        passes = std::set<std::string>();
        for ( const auto& [pass, x] : creators ) {
            if ( x.second == 0 ) // phase == 0 -> run at hardcoded places only
                continue;

            if ( ! uses_cfg.contains(pass) )
                passes->insert(pass);
        }

        if ( has_cfg ) {
            for ( const auto& pass : uses_cfg )
                passes->insert(pass);
        }
    }

    Phase max_phase{};
    for ( const auto& [_, x] : creators )
        max_phase = std::max(x.second, max_phase);

    size_t round = 0;

    bool ever_modified = false;

    // Run the phases in order in a loop until we reach a fixpoint.
    while ( true ) {
        bool modified = false;

        // Run the phases in order.
        for ( Phase phase = 0; phase <= max_phase; ++phase ) {
            // Run all passes in a phase until we reach a fixpoint for the phase.
            while ( true ) {
                auto inner_modified = false;

                // Filter out passes to run in this phase.
                // NOTE: We do not use `util::transform` here to guarantee a consistent order of the visitors.
                std::vector<std::unique_ptr<OptimizerVisitor>> vs;
                vs.reserve(passes->size());
                for ( const auto& pass : *passes ) {
                    if ( creators.contains(pass) ) {
                        auto&& [create, phase_] = getPassRegistry()->creators().at(pass);

                        if ( phase_ != phase )
                            continue;

                        vs.push_back(create(builder, &op_uses));
                    }
                }

                for ( auto& v : vs ) {
                    HILTI_DEBUG(logging::debug::OptimizerCollect,
                                util::fmt("processing AST, round=%d, phase = %d", round, phase));
                    v->collect(root);
                    inner_modified = v->pruneUses(root) || inner_modified;
                    inner_modified = v->pruneDecls(root) || inner_modified;
                };

                modified = modified || inner_modified;
                if ( ! inner_modified )
                    break;

                ++round;
            }

            // Clean up simplified code with peephole optimizer.
            while ( true ) {
                const auto& creator_peephole_optimizer = creators.at("peephole");
                auto v = (creator_peephole_optimizer.first)(builder, nullptr);
                visitor::visit(*v, root);
                if ( ! v->isModified() )
                    break;
            }
        }

        ever_modified |= modified;
        if ( ! modified )
            break;
    }

    // Clear cached information which might become outdated due to edits.
    auto v = hilti::visitor::PreOrder();
    for ( auto* n : hilti::visitor::range(v, root, {}) )
        n->clearScope();

    return ever_modified;
}

} // namespace hilti
