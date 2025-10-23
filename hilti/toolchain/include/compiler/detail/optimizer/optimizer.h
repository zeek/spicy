// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/builder/builder.h>
#include <hilti/ast/forward.h>
#include <hilti/ast/visitor.h>
#include <hilti/base/logger.h>
#include <hilti/base/timing.h>
#include <hilti/compiler/detail/cfg.h>
#include <hilti/compiler/detail/optimizer/pass-id.h>

namespace hilti::logging::debug {
inline const hilti::logging::DebugStream Optimizer("optimizer");
inline const hilti::logging::DebugStream OptimizerPasses("optimizer-passes");
inline const hilti::logging::DebugStream OptimizerDump("optimizer-dump");
} // namespace hilti::logging::debug

namespace hilti::detail {

class Optimizer;

namespace optimizer {

struct PassInfo;

namespace visitor {
class Collector;
class Mutator;
} // namespace visitor

/**
 * Tracks the current state of the AST during optimization.
 *
 * An optimizer instance maintains one such state object that persists across
 * all optimization passes. The state is provided to all optimization passes
 * and acts primarily as a source for knowledge about the AST. Internally, it
 * also tracks modifications made to the AST so far, and provides helper
 * functions to update the AST later as needed by those modifications.
 */
class ASTState {
public:
    /** Returns the AST context being optimized. */
    auto* context() { return _context; }

    /**
     * While a pass is running, returns information about it.
     *
     * Must not be called when no pass is active. In other words, call it only
     * from inside a pass's `run()` callback.
     *
     * @return the pass info
     */
    const auto& pass() const {
        assert(_pinfo);
        return *_pinfo;
    }

    /**
     * Returns the control flow graph for the given block.
     *
     * The CFG is created on first request and cached for subsequent calls,
     * until the block or its containing function/module is modified.
     *
     * @param block the block to get the CFG for, which must be part of a
     * function or module
     * @return the CFG (which will actually be the CFG for the outermost block
     * containing the given block, i.e., the function or module body containing
     * it)
     */
    CFG* cfg(statement::Block* block);

protected:
    friend class hilti::detail::Optimizer;
    friend class visitor::Collector;
    friend class visitor::Mutator;

    /**
     * Constructor.
     *
     * @param ctx the AST context being optimized
     * @param builder the AST builder to use for AST changes by optimization passes
     */
    ASTState(ASTContext* ctx, Builder* builder) : _context(ctx), _builder(builder) {}

    /**
     * Records a pass as the one currently running.
     *
     * @param pinfo the info for the pass to record
     * @return a scope guard that unsets the current pass when it goes out of scope
     */
    auto trackPass(const PassInfo* pinfo) {
        _pinfo = pinfo;
        return util::scope_exit([&]() { _pinfo = nullptr; });
    }

    /**
     * Records that a function part of the AST has been modified. This will
     * later trigger a re-computation of state related to that function by
     * `updateAST()`.
     */
    void functionChanged(hilti::Function* function);

    /**
     * Records that a module part of the AST has been modified. This will later
     * trigger a re-computation of state related to that module by
     * `updateAST()`.
     */
    void moduleChanged(declaration::Module* module);

    /**
     * Updates the AST state after modifications made by a pass. This may run
     * additional visitors over the AST, such as the HILTI resolver, based on
     * (1) modifications recorded by `functionChanged()` and `moduleChanged()`;
     * and (2) any AST post-processing the pass needs after its modifications.
     * Assuming that the pass (1) properly recorded all modifications it made,
     * and (2) correctly specified any guarantees it provides about the AST
     * state after its processing, the AST will be in a fully resolved &
     * consistent state afterwards, ready for other optimization passes to run,
     * or the optimizer to finish.
     *
     * @param pinfo the info for the pass that made the modifications
     */
    void updateAST(const optimizer::PassInfo& pinfo);

#ifndef NDEBUG
    /**
     * Runs a series on internal consistency checks on the AST. This re-runs
     * various checks and visitors over the AST, including a full resolver
     * pass, to ensure that the AST is in a fully resolved & consistent state.
     * It will abort execution with an internal error if it finds any issues
     * with the AST. As this method is expensive, it is only available in debug
     * builds.
     *
     * @param pass_id the ID of the pass after which the check is being run for
     * debug logging
     */
    void checkAST(PassID pass_id);
#endif

private:
    // When we have collected all modifications for a pass, prepares the state
    // for upcoming use by `updateAST()`.
    void _normalizeModificationState();

    ASTContext* _context = nullptr;
    Builder* _builder = nullptr;
    const PassInfo* _pinfo = nullptr;

    std::unordered_map<Function*, declaration::Module*>
        _modified_functions;                                    // maps modified functions to its containing module
    std::unordered_set<declaration::Module*> _modified_modules; // set of modified modules

    std::unordered_map<statement::Block*, std::unique_ptr<CFG>> _cfgs; // cached CFGs
};

/**
 * Enum specifying post-processing steps that optimization passes do *not*
 * require after processing an AST. Generally, after each pass, the optimizer
 * will re-run various resolver visitors to bring it back into a fully resolved
 * and consistent state. For efficiency, passes can indicate through a bitmask
 * which of those steps they do not require, because they guarantee that their
 * modifications will not have invalidated those aspects of the AST.
 */
enum class Guarantees : uint16_t {
    CFGUnchanged = (1U << 1U),    /**< control flow graphs remain unchanged even for modified functions */
    ConstantsFolded = (1U << 2U), /**< all constant expressions remain fully folded */
    FullyResolved = (1U << 3U),   /**< AST remains fully resolved with regards to anything the AST resolver does */
    ResolvedExceptCoercions = (1U << 4U), /**< AST remains fully resolved with regards to anything the AST resolver
                                             does, except that coercions might not be fully executed */
    ScopesBuilt = (1U << 5U),             /**< the scopes of all nodes remain valid */
    TypesUnified = (1U << 6U),            /**< all types remain fully unified */

    None = 0U,               /**< no guarantees provided, recompute everything */
    All = ((1U << 16U) - 1U) /**< AST still fully up to date in all regards, nothing to recompute */
};

extern std::string to_string(bitmask<Guarantees> r);

/**
 * Information describing an optimization pass, telling the optimizer when and
 * how to run it, and in what state it will leave the AST.
 *
 * More specifically, we rely on the following contract between the optimizer
 * and an optimization pass:
 *
 * - The pass's `run()` callback will be called by the optimizer to perform any
 *   modifications on the AST as desired. The optimizer guarantees that at the
 *   time of the call, the AST is in a fully resolved, consistent, and
 *   validated state, just as if it had come out of the pre-optimizer AST
 *   processing.
 *
 * - The pass is free to perform any modifications on the AST. However, it must
 *   do so only inside a class derived from `optimizer::visitor::Mutator`, and
 *   use the APIs provided by that class (incl. any of its bases) to make, or
 *   at least record, changes. That means that for node replacements or
 *   removals, it should generally call the corresponding `replaceNode()` or
 *   `removeNode()` methods. For other types of changes (including
 *   replacements/removals that cannot be expressed directly through those
 *   methods), it can make them directly to the AST, but must call the
 *   mutator's `recordChange()` method to inform the optimizer about it. This
 *   is so that the optimizer can track what parts of the AST have been
 *   modified, to later potentially re-compute their AST state.
 *
 * - When the pass finishes, it must indicate through its return type whether
 *   modifications have been made. This should usually just be the result of
 *   the `Modifier`'s` ``run()` method (which, in turn, is the mutator's
 *   `isModified()` state).
 *
 * - When the pass finishes, optimizer will run post-processing on the parts of
 *   the AST that were modified to bring the AST back into a fully resolved and
 *   consistent state, before it then proceeds with further passes or
 *   eventually hands off to code generation. Optionally, the pass can indicate
 *   through its `guarantees` field any post-processing steps the optimizer can
 *   skip because the pass won't have modified anything pertaining to those
 *   steps.
 */
struct PassInfo {
    /**
     * Callback executing the pass's main logic. This will typically run a
     * `visitor::Mutator` over the AST to make modifications as desired; see
     * the contract described above. The callback must return true if it
     * modified the AST, false otherwise.
     */
    using Callback = bool (*)(Optimizer* opt);

    PassID id;             /**< pass's unique ID, also defining the order among passes when to run */
    bool one_time = false; /**< if true, the pass runs only once in the first round */
    bool iterate = false;  /**< if true, the pass is re-run until it makes no further modifications */
    bitmask<Guarantees> guarantees = Guarantees::None; /**< AST guarantees the pass provides after processing */
    Callback run; /**< the callback executing the pass's main logic, per the contract described above */

    bool operator<(const PassInfo& other) const { return id < other.id; }
};

} // namespace optimizer

/** The HILTI optimizer, applying a series of optimization passes to an AST. */
class Optimizer {
public:
    /**
     * Creates a new optimizer for the given AST context.
     *
     * @param ctx the AST context to operator on
     */
    Optimizer(ASTContext* ctx);

    /**
     * Applies all optimizations to an AST. The AST must have been fully
     * resolved before running optimization, and will be returned fully resolved
     * as well.
     *
     * @return `Nothing` on success, error otherwise
     */
    hilti::Result<Nothing> run();

    /** Returns the AST context being optimized. */
    auto* context() { return _context; }

    /** Returns the AST builder to use for AST changes by optimization passes. */
    auto* builder() { return &_builder; }

    /**
     * Returns the current AST state.
     *
     * The state persists across the lifetime of the optimizer instance. It
     * reflects, and records, the progress of the optimization so far.
     */
    optimizer::ASTState* state() { return &_state; }

    // Static helper functions that optimization passes may find useful.

    /**
     * Returns true if the given ID names a feature flag.
     *
     * @param id the ID to check
     */
    static bool isFeatureFlag(const ID& id) { return util::startsWith(id.local(), "__feat%"); }

    /**
     * Extracts tuple `(id, feature)` from a feature constant ID.
     *
     * @param feature_constant the feature constant ID
     */
    static std::optional<std::pair<ID, std::string>> idFeatureFromConstant(const ID& feature_constant);

private:
    // Executes one turn of a single optimization pass, updating AST state
    // afterwards as needed.
    bool _runPass(const optimizer::PassInfo& pinfo, unsigned int round);

    // Dumps node and source code representations of the current AST to files
    // for debugging.
    void _dumpAST(ASTContext* ctx, std::string_view fname, std::string_view header);

    ASTContext* _context;
    Builder _builder;
    optimizer::ASTState _state;
};

} // namespace hilti::detail

enableEnumClassBitmask(hilti::detail::optimizer::Guarantees); // must be in global scope
