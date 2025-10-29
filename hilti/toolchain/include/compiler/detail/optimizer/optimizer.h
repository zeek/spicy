// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/builder/builder.h>
#include <hilti/ast/forward.h>
#include <hilti/ast/visitor.h>
#include <hilti/base/logger.h>
#include <hilti/base/timing.h>

namespace hilti::logging::debug {
inline const hilti::logging::DebugStream Optimizer("optimizer");
inline const hilti::logging::DebugStream OptimizerDetail("optimizer-detail");
inline const hilti::logging::DebugStream OptimizerDump("optimizer-dump");
} // namespace hilti::logging::debug

namespace hilti::detail {
namespace optimizer {

enum class Phase {
    // Note: Keep these ordered in the sequence they will run, we're the enum values for debug output.
    Init,   // Will run exactly once before we process any of the other phases for the first time.
    Phase1, // Will run until convergence with all other passes of the same phase.
    Phase2, // Will run until convergence with all other passes of the same phase.
    Phase3, // Will run until convergence with all other passes of the same phase.
    Post,   // Will run once each time the regular phases have finished.
};

namespace detail {
constexpr util::enum_::Value<Phase> Phases[] = {
    {.value = Phase::Init, .name = "pre-processing phase"},
    {.value = Phase::Phase1, .name = "phase 1"},
    {.value = Phase::Phase2, .name = "phase 2"},
    {.value = Phase::Phase3, .name = "phase 3"},
    {.value = Phase::Post, .name = "post-processing phase"},
};
}

constexpr auto to_string(Phase p) { return util::enum_::to_string(p, detail::Phases); }

struct PassInfo;

struct ASTState {
    using OperatorUses = std::map<const Operator*, std::vector<expression::ResolvedOperator*>>;

    ASTState(ASTContext* ctx) : context(ctx) { update(); }

    ASTContext* context = nullptr;
    const PassInfo* pass = nullptr;
    unsigned int round = 0;
    OperatorUses op_uses;

    const OperatorUses::mapped_type* uses(const Operator* x) const {
        if ( ! op_uses.contains(x) )
            return nullptr;

        return &op_uses.at(x);
    }

    // TODO: This just recomputes everything, make this all smarter somehow.
    void update();
};

} // namespace optimizer

class Optimizer {
public:
    Optimizer(ASTContext* ctx);

    /**
     * Applies optimizations to an AST. The AST must have been fully processed
     * before running optimization. This can be run multiple times if the same AST
     * needs to be re-optimized.
     */
    bool run();

    auto* builder() { return &_builder; }
    auto* context() { return _context; }
    auto* state() { return _state; }

    // TODO: Figure out where to put these.
    QualifiedType* innermostType(QualifiedType* type);
    std::optional<std::pair<ID, std::string>> idFeatureFromConstant(const ID& feature_constant);
    bool isFeatureFlag(const ID& id) { return util::startsWith(id.local(), "__feat%"); }

private:
    bool _runPhase(optimizer::Phase phase, bool iterate);
    void _dumpAST(ASTContext* ctx, std::string_view fname, std::string_view header);

    ASTContext* _context;
    Builder _builder;

    optimizer::ASTState* _state = nullptr;
    int _runs = 0;
};


} // namespace hilti::detail
