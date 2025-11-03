// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include "hilti/hilti/compiler/detail/optimizer/optimizer.h"

#include <optional>
#include <string>

#include <hilti/ast/builder/builder.h>
#include <hilti/base/timing.h>
#include <hilti/hilti/hilti/compiler/detail/optimizer/pass.h>

using namespace hilti;
using namespace hilti::detail;
using namespace hilti::detail::optimizer;

// Collects uses of resolved operators
struct CollectUsesPass : public hilti::visitor::PreOrder {
    ASTState::OperatorUses result;

    ASTState::OperatorUses collect(Node* node) {
        hilti::visitor::visit(*this, node);
        return result;
    }

    void operator()(expression::ResolvedOperator* node) override { result[&node->operator_()].push_back(node); }
};

void ASTState::update() {
    CollectUsesPass collect_uses{};
    op_uses = collect_uses.collect(context->root());
}

Optimizer::Optimizer(ASTContext* ctx) : _context(ctx), _builder(ctx) {}

void Optimizer::_dumpAST(ASTContext* ctx, std::string_view fname, std::string_view header) {
    std::ofstream out_ast(util::fmt("optimizer-ast-%s.tmp", fname));
    out_ast << " # " << header << "\n\n";
    ctx->dump(out_ast, true);

    std::ofstream out_hlt(util::fmt("optimizer-hlt-%s.tmp", fname));
    out_hlt << header;
    ctx->root()->print(out_hlt, false, true);
}

bool Optimizer::_runPhase(Phase phase, bool iterate) {
    const auto& passes = getPassRegistry()->passes(phase);
    if ( passes.empty() )
        return false;

    HILTI_DEBUG(logging::debug::Optimizer, util::fmt("processing AST, %s", to_string(phase)));
    logging::DebugPushIndent _(logging::debug::Optimizer);

    int round = 0;
    bool modified = false;
    bool ever_modified = false;

    do {
        if ( ++round >= 50 )
            logger().internalError("optimizer::runPhase() didn't terminate, AST keeps changing");

        modified = false;
        int phase_index = 0;
        for ( const auto& pinfo : getPassRegistry()->passes(phase) ) {
            HILTI_DEBUG(logging::debug::Optimizer,
                        util::fmt("pass: %s (round %d, phase index %d)", pinfo.name, round, phase_index));

            ASTState state(context());
            state.pass = &pinfo;
            state.round = round; // TODO: Do we need this, and if so is this the right value?

            auto _ = util::scope_exit([&]() { _state = nullptr; });
            _state = &state;

            {
                logging::DebugPushIndent _(logging::debug::Optimizer);
                util::timing::Collector __(util::fmt("hilti/compiler/optimizer/%s", pinfo.name));

                if ( (*pinfo.run)(this) == optimizer::Result::Modified ) {
                    HILTI_DEBUG(logging::debug::Optimizer, "-> AST modified");
                    modified = true;
                    ever_modified = true;

                    if ( logger().isEnabled(logging::debug::OptimizerDump) ) {
                        const auto fname =
                            util::fmt("%d-%d-%d-%d-%s", static_cast<int>(phase), _runs, round, phase_index, pinfo.name);
                        const auto header =
                            util::fmt("State after modifications by pass %s, round %d, phase index %d\n", pinfo.name,
                                      round, phase_index);
                        _dumpAST(context(), fname, header);
                    }
                }
            }

            ++phase_index;
        }

    } while ( iterate && modified );

    return ever_modified;
}

bool Optimizer::run() {
    util::timing::Collector _("hilti/compiler/optimizer");

    ++_runs;
    const bool first_run = (_runs == 1);

    if ( first_run && logger().isEnabled(logging::debug::OptimizerDump) )
        _dumpAST(context(), "0-0-0-0-initial", "Initial state before optimization");

    bool modified = false;

    if ( first_run )
        modified |= _runPhase(Phase::Init, false);

    modified |= _runPhase(Phase::Phase1, true);
    modified |= _runPhase(Phase::Phase2, true);
    modified |= _runPhase(Phase::Phase3, true);
    modified |= _runPhase(Phase::Post, false);

    if ( logger().isEnabled(logging::debug::OptimizerDump) )
        _dumpAST(context(), util::fmt("%d-x-x-x-final", _runs), "Final state after optimization");

    return modified;
}


// Helper function to extract innermost type, removing any wrapping in reference or container types.
QualifiedType* Optimizer::innermostType(QualifiedType* type) {
    if ( type->type()->isReferenceType() )
        return innermostType(type->type()->dereferencedType());

    if ( type->type()->iteratorType() )
        return innermostType(type->type()->elementType());

    return type;
}

// Helper to extract `(ID, feature)` from a feature constant.
std::optional<std::pair<ID, std::string>> Optimizer::idFeatureFromConstant(const ID& feature_constant) {
    const auto& id = feature_constant.local();

    if ( ! isFeatureFlag(id) )
        return {};

    const auto& tokens = util::split(id, "%");
    assert(tokens.size() == 3);

    auto type_id = ID(util::replace(tokens[1], "@@", "::"));
    const auto& feature = tokens[2];

    return {{type_id, feature}};
};
