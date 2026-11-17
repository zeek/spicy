// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <algorithm>

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
    if ( const auto* cases = std::get_if<SwitchPayload>(&terminator.payload) ) {
        std::vector<BlockId> out;
        for ( const auto& c : cases->cases )
            out.push_back(c.target);
        out.push_back(cases->default_target);
        return out;
    }

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

            // Several successors of a block may be the same, so the edges are deduplicated.
            auto target = cfg.position.at(to.index);
            if ( std::ranges::find(cfg.successors[from], target) != cfg.successors[from].end() )
                continue;
            cfg.successors[from].emplace_back(target);
            cfg.predecessors[target].emplace_back(from);
        }
    }

    return cfg;
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

} // namespace spicy::detail::pir::ir
