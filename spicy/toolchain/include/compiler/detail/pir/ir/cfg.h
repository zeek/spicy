// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <cstddef>
#include <optional>
#include <unordered_map>
#include <vector>

#include <spicy/compiler/detail/pir/ir/package.h>

namespace spicy::detail::pir::ir {

/** Marks a position that no analysis result names, such as an unreachable one. */
inline constexpr size_t NoPosition = static_cast<size_t>(-1);

/**
 * The control-flow graph of one region. Positions index `blocks`, whose first entry is the entry block.
 * Successor edges that leave the region are omitted; the verifier reports them separately.
 */
struct Cfg {
    std::vector<BlockId> blocks;
    std::unordered_map<uint32_t, size_t> position; /**< block index to its position in `blocks` */
    std::vector<std::vector<size_t>> successors;
    std::vector<std::vector<size_t>> predecessors;

    bool contains(BlockId block) const { return position.contains(block.index); }
};

/**
 * The immediate post-dominator of one block. The analysis uses a synthetic exit that every returning block
 * reaches. `Exit` names that node, which is not a block of the region, so it never becomes a branch target.
 */
struct PostDominator {
    enum class Kind {
        Block,  /**< `position` is a block of the region */
        Exit,   /**< the synthetic exit: no block of the region post-dominates this one */
        NoExit, /**< the block cannot reach any exit */
    };

    Kind kind = Kind::NoExit;
    size_t position = NoPosition; /**< set only for `Kind::Block` */
};

/** The successor blocks named by a block's terminator, in payload order; empty for a return or finish. */
std::vector<BlockId> successorBlocks(const Package& package, BlockId block);

/** Builds the graph of `region`, whose first block is the entry. */
Cfg buildCfg(const Package& package, RegionId region);

/** Whether no path through `cfg` returns to a block it has already passed. */
bool isAcyclic(const Cfg& cfg);

/**
 * The positions reachable from `entry` in depth-first postorder, following successors in their order. Cycles are
 * tolerated, and each reachable position appears once. Reversing the result gives a topological order for acyclic
 * graphs.
 */
std::vector<size_t> postorder(const std::vector<std::vector<size_t>>& successors, size_t entry);

/**
 * Immediate dominators over the graph given by `successors`, rooted at `entry`. The entry dominates itself, and
 * a position unreachable from `entry` has `NoPosition`.
 */
std::vector<size_t> immediateDominators(const std::vector<std::vector<size_t>>& successors, size_t entry);

/** Whether `dominator` dominates `position`, given the immediate dominators from `immediateDominators()`. */
bool dominates(const std::vector<size_t>& immediate_dominators, size_t dominator, size_t position);

/** The immediate post-dominator of each position of `cfg`, with the synthetic exit kept distinct. */
std::vector<PostDominator> immediatePostDominators(const Cfg& cfg);

/**
 * Where the two arms of each branch rejoin, indexed by position; empty for a position that is not a branch, and
 * for a branch whose arms never rejoin. A branch rejoins at its immediate post-dominator when that is a block.
 * Otherwise an early return cuts across it, and the join is the earliest block that both arms reach.
 */
std::vector<std::optional<size_t>> branchJoins(const Cfg& cfg);

/**
 * Whether `cfg` can be emitted as nested structured control flow with the given joins. Each branch's arms run up
 * to its join, which then follows them at the enclosing level. The emission is structured only if no block is
 * reached twice.
 */
bool isStructured(const Cfg& cfg, const std::vector<std::optional<size_t>>& joins);

} // namespace spicy::detail::pir::ir
