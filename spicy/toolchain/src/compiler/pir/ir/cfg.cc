// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <algorithm>
#include <array>

#include <spicy/compiler/detail/pir/ir/cfg.h>

namespace spicy::detail::pir::ir {

std::vector<BlockId> successorBlocks(const Package& package, BlockId block) {
    const auto& insts = package.block(block).insts;
    if ( insts.empty() || ! package.isValid(insts.back()) )
        return {};

    const auto& terminator = package.inst(insts.back());
    if ( const auto* branch = std::get_if<BranchPayload>(&terminator.payload) )
        return {branch->then_block, branch->else_block};
    if ( const auto* jump = std::get_if<JumpPayload>(&terminator.payload) )
        return {jump->target};

    return {};
}

Cfg buildCfg(const Package& package, RegionId region) {
    Cfg cfg;
    for ( auto block : package.region(region).blocks ) {
        if ( ! package.isValid(block) || cfg.contains(block) )
            continue;

        cfg.position.emplace(block.index, cfg.blocks.size());
        cfg.blocks.emplace_back(block);
    }

    cfg.successors.resize(cfg.blocks.size());
    cfg.predecessors.resize(cfg.blocks.size());
    for ( size_t from = 0; from < cfg.blocks.size(); ++from ) {
        for ( auto to : successorBlocks(package, cfg.blocks[from]) ) {
            if ( ! cfg.contains(to) )
                continue;

            auto target = cfg.position.at(to.index);
            cfg.successors[from].emplace_back(target);
            cfg.predecessors[target].emplace_back(from);
        }
    }

    return cfg;
}

bool isAcyclic(const Cfg& cfg) {
    // Kahn's algorithm: every position is removed exactly when all of its predecessors have been.
    std::vector<size_t> pending(cfg.blocks.size());
    std::vector<size_t> ready;
    for ( size_t i = 0; i < cfg.blocks.size(); ++i ) {
        pending[i] = cfg.predecessors[i].size();
        if ( pending[i] == 0 )
            ready.emplace_back(i);
    }

    size_t removed = 0;
    while ( ! ready.empty() ) {
        auto current = ready.back();
        ready.pop_back();
        ++removed;

        for ( auto next : cfg.successors[current] )
            if ( --pending[next] == 0 )
                ready.emplace_back(next);
    }

    return removed == cfg.blocks.size();
}

std::vector<size_t> postorder(const std::vector<std::vector<size_t>>& successors, size_t entry) {
    std::vector<size_t> order;
    std::vector<bool> visited(successors.size(), false);
    std::vector<std::pair<size_t, size_t>> stack = {{entry, 0}};
    visited[entry] = true;
    while ( ! stack.empty() ) {
        auto [node, next] = stack.back();
        if ( next < successors[node].size() ) {
            stack.back().second = next + 1;
            auto target = successors[node][next];
            if ( ! visited[target] ) {
                visited[target] = true;
                stack.emplace_back(target, 0);
            }
            continue;
        }

        order.emplace_back(node);
        stack.pop_back();
    }

    return order;
}

std::vector<size_t> immediateDominators(const std::vector<std::vector<size_t>>& successors, size_t entry) {
    const auto count = successors.size();
    std::vector<std::vector<size_t>> predecessors(count);
    for ( size_t from = 0; from < count; ++from )
        for ( auto to : successors[from] )
            predecessors[to].emplace_back(from);

    // Reverse postorder from the entry; unreachable positions are never numbered.
    auto reverse_postorder = postorder(successors, entry);
    std::ranges::reverse(reverse_postorder);

    std::vector<size_t> order(count, NoPosition);
    for ( size_t i = 0; i < reverse_postorder.size(); ++i )
        order[reverse_postorder[i]] = i;

    // Cooper, Harvey, and Kennedy's iterative algorithm, which intersects along the dominator tree built so far.
    std::vector<size_t> idom(count, NoPosition);
    idom[entry] = entry;
    auto intersect = [&](size_t a, size_t b) {
        while ( a != b ) {
            while ( order[a] > order[b] )
                a = idom[a];
            while ( order[b] > order[a] )
                b = idom[b];
        }
        return a;
    };

    for ( bool changed = true; changed; ) {
        changed = false;
        for ( auto node : reverse_postorder ) {
            if ( node == entry )
                continue;

            size_t updated = NoPosition;
            for ( auto pred : predecessors[node] ) {
                if ( idom[pred] == NoPosition )
                    continue;

                updated = updated == NoPosition ? pred : intersect(pred, updated);
            }

            if ( updated != idom[node] ) {
                idom[node] = updated;
                changed = true;
            }
        }
    }

    return idom;
}

bool dominates(const std::vector<size_t>& immediate_dominators, size_t dominator, size_t position) {
    if ( position >= immediate_dominators.size() || immediate_dominators[position] == NoPosition )
        return false;

    for ( auto node = position;; node = immediate_dominators[node] ) {
        if ( node == dominator )
            return true;
        if ( immediate_dominators[node] == node )
            return false;
    }
}

std::vector<PostDominator> immediatePostDominators(const Cfg& cfg) {
    // The reversed graph has one extra position, the synthetic exit, which precedes every block without successors.
    const auto count = cfg.blocks.size();
    const auto exit = count;
    std::vector<std::vector<size_t>> reversed(count + 1);
    for ( size_t i = 0; i < count; ++i ) {
        reversed[i] = cfg.predecessors[i];
        if ( cfg.successors[i].empty() )
            reversed[exit].emplace_back(i);
    }

    auto idom = immediateDominators(reversed, exit);
    std::vector<PostDominator> result(count);
    for ( size_t i = 0; i < count; ++i ) {
        if ( idom[i] == NoPosition )
            result[i] = {.kind = PostDominator::Kind::NoExit};
        else if ( idom[i] == exit )
            result[i] = {.kind = PostDominator::Kind::Exit};
        else
            result[i] = {.kind = PostDominator::Kind::Block, .position = idom[i]};
    }

    return result;
}

namespace {

// The positions reachable from `start` without entering `stop`, which itself is never marked. `start` is marked
// unless it is `stop`.
std::vector<bool> reachableAvoiding(const Cfg& cfg, size_t start, std::optional<size_t> stop) {
    std::vector<bool> reached(cfg.blocks.size(), false);
    std::vector<size_t> pending = {start};
    while ( ! pending.empty() ) {
        auto next = pending.back();
        pending.pop_back();
        if ( (stop && next == *stop) || reached[next] )
            continue;

        reached[next] = true;
        pending.insert(pending.end(), cfg.successors[next].begin(), cfg.successors[next].end());
    }

    return reached;
}

// Whether the two arms of a branch rejoin at `join` (or do not rejoin at all, if nothing is given) without any block
// being emitted twice. Each arm's blocks up to the join must be disjoint from the other arm's, and from the blocks
// that follow the join.
bool rejoinsAt(const Cfg& cfg, std::array<size_t, 2> arms, std::optional<size_t> join) {
    auto first = reachableAvoiding(cfg, arms[0], join);
    auto second = reachableAvoiding(cfg, arms[1], join);
    auto after = join ? reachableAvoiding(cfg, *join, std::nullopt) : std::vector<bool>(cfg.blocks.size(), false);

    for ( size_t i = 0; i < cfg.blocks.size(); ++i ) {
        if ( first[i] && second[i] )
            return false;
        if ( after[i] && (first[i] || second[i]) )
            return false;
    }

    return true;
}

} // namespace

std::vector<std::optional<size_t>> branchJoins(const Cfg& cfg) {
    std::vector<std::optional<size_t>> joins(cfg.blocks.size());
    if ( cfg.blocks.empty() )
        return joins;

    auto post_dominators = immediatePostDominators(cfg);
    auto topological = postorder(cfg.successors, 0);
    std::ranges::reverse(topological);

    for ( size_t pos = 0; pos < cfg.blocks.size(); ++pos ) {
        if ( cfg.successors[pos].size() != 2 )
            continue;

        const std::array<size_t, 2> arms = {cfg.successors[pos][0], cfg.successors[pos][1]};

        // The immediate post-dominator comes first. An early return cuts across it, so the other candidates are
        // the blocks either arm reaches, in topological order.
        std::vector<size_t> candidates;
        if ( post_dominators[pos].kind == PostDominator::Kind::Block )
            candidates.emplace_back(post_dominators[pos].position);

        auto from_first = reachableAvoiding(cfg, arms[0], std::nullopt);
        auto from_second = reachableAvoiding(cfg, arms[1], std::nullopt);
        for ( auto candidate : topological ) {
            if ( from_first[candidate] || from_second[candidate] )
                candidates.emplace_back(candidate);
        }

        for ( auto candidate : candidates ) {
            if ( rejoinsAt(cfg, arms, candidate) ) {
                joins[pos] = candidate;
                break;
            }
        }
    }

    return joins;
}

bool isStructured(const Cfg& cfg, const std::vector<std::optional<size_t>>& joins) {
    // Mirrors the emission order: a branch emits its arms up to its join, then continues from the join.
    std::vector<bool> emitted(cfg.blocks.size(), false);
    bool structured = true;

    auto walk_range = [&](auto&& self, size_t pos, std::optional<size_t> stop) -> void {
        while ( structured && pos != stop.value_or(NoPosition) ) {
            if ( emitted[pos] ) {
                structured = false;
                return;
            }
            emitted[pos] = true;

            const auto& next = cfg.successors[pos];
            if ( next.empty() )
                return;

            if ( next.size() == 1 ) {
                pos = next[0];
                continue;
            }

            self(self, next[0], joins[pos]);
            self(self, next[1], joins[pos]);
            if ( ! joins[pos] )
                return;

            pos = *joins[pos];
        }
    };

    walk_range(walk_range, 0, std::nullopt);
    return structured;
}

} // namespace spicy::detail::pir::ir
