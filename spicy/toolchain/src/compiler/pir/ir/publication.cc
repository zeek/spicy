// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <algorithm>
#include <iterator>
#include <map>
#include <optional>

#include <spicy/compiler/detail/pir/ir/cfg.h>
#include <spicy/compiler/detail/pir/ir/publication.h>

namespace spicy::detail::pir::ir {

namespace {

// The fields published so far, by the index of the unit's origin.
struct Published {
    std::map<uint32_t, std::set<uint32_t>> may;  /**< on some path */
    std::map<uint32_t, std::set<uint32_t>> must; /**< on every path */

    friend bool operator==(const Published&, const Published&) = default;
};

Published merge(const Published& a, const Published& b) {
    Published out = a;
    for ( const auto& [origin, fields] : b.may )
        out.may[origin].insert(fields.begin(), fields.end());

    // A unit missing from one side has nothing published there.
    out.must.clear();
    for ( const auto& [origin, fields] : a.must ) {
        auto other = b.must.find(origin);
        if ( other == b.must.end() )
            continue;
        std::set<uint32_t> both;
        std::ranges::set_intersection(fields, other->second, std::inserter(both, both.begin()));
        out.must.emplace(origin, std::move(both));
    }
    return out;
}

} // namespace

Publications analyzePublications(const Package& package, FunctionId function) {
    Publications result;
    if ( ! package.isValid(function) || ! package.isValid(package.function(function).root_region) )
        return result;

    auto cfg = buildCfg(package, package.function(function).root_region);
    if ( cfg.blocks.empty() )
        return result;

    // Origins flow through publications and Phis of reachable blocks. A Phi may precede its Upsilons in block order, so
    // this iterates to a fixpoint.
    std::vector<InstId> body;
    for ( auto pos : postorder(cfg.successors, 0) )
        for ( auto id : package.block(cfg.blocks[pos]).insts )
            if ( package.isValid(id) )
                body.push_back(id);

    std::unordered_map<uint32_t, std::set<uint32_t>> origins;
    for ( bool changed = true; changed; ) {
        changed = false;
        auto add = [&](InstId to, const std::set<uint32_t>& from) {
            auto& set = origins[to.index];
            auto size = set.size();
            set.insert(from.begin(), from.end());
            changed = changed || set.size() != size;
        };
        for ( auto id : body ) {
            const auto& inst = package.inst(id);
            if ( inst.opcode == Opcode::UnitCreate )
                add(id, {id.index});
            else if ( inst.opcode == Opcode::PublishField && ! inst.args.empty() &&
                      origins.contains(inst.args[0].index) )
                add(id, origins[inst.args[0].index]);
            else if ( inst.opcode == Opcode::Upsilon && ! inst.args.empty() && origins.contains(inst.args[0].index) ) {
                const auto* payload = std::get_if<UpsilonPayload>(&inst.payload);
                if ( payload && package.isValid(payload->phi) && package.inst(payload->phi).opcode == Opcode::Phi )
                    add(payload->phi, origins[inst.args[0].index]);
            }
        }
    }

    for ( const auto& [value, set] : origins ) {
        if ( set.empty() )
            continue;
        // Only a Phi merges origins; values derived from it inherit the mix, which the Phi already reports.
        if ( set.size() > 1 ) {
            if ( package.inst(InstId{value}).opcode == Opcode::Phi )
                result.mixed_phis.push_back(InstId{value});
            continue;
        }
        result.origins.emplace(value, InstId{*set.begin()});
    }
    std::ranges::sort(result.mixed_phis, {}, &InstId::index);

    auto origin = [&](InstId value) -> std::optional<uint32_t> {
        auto it = result.origins.find(value.index);
        return it == result.origins.end() ? std::nullopt : std::optional(it->second.index);
    };

    auto transfer = [&](BlockId block, Published& state, bool report) {
        for ( auto id : package.block(block).insts ) {
            if ( ! package.isValid(id) )
                continue;
            const auto& inst = package.inst(id);
            if ( inst.opcode == Opcode::PublishField && ! inst.args.empty() ) {
                const auto* payload = std::get_if<FieldPayload>(&inst.payload);
                auto unit = origin(inst.args[0]);
                if ( ! payload || ! unit )
                    continue;
                if ( report && state.may[*unit].contains(payload->field.index) )
                    result.duplicates.push_back(id);
                state.may[*unit].insert(payload->field.index);
                state.must[*unit].insert(payload->field.index);
            }
            else if ( inst.opcode == Opcode::Finish && report && inst.args.size() == 2 ) {
                auto unit = origin(inst.args[1]);
                result.finished.emplace_back(id, unit ? state.must[*unit] : std::set<uint32_t>{});
            }
        }
    };

    std::vector<std::optional<Published>> in(cfg.blocks.size());
    in[0] = Published{};
    std::vector<size_t> worklist = {0};
    while ( ! worklist.empty() ) {
        auto pos = worklist.back();
        worklist.pop_back();
        auto state = *in[pos];
        transfer(cfg.blocks[pos], state, false);
        for ( auto next : cfg.successors[pos] ) {
            auto merged = in[next] ? merge(*in[next], state) : state;
            if ( in[next] != merged ) {
                in[next] = std::move(merged);
                worklist.push_back(next);
            }
        }
    }

    for ( size_t pos = 0; pos < cfg.blocks.size(); ++pos ) {
        if ( ! in[pos] )
            continue;
        auto state = *in[pos];
        transfer(cfg.blocks[pos], state, true);
    }

    return result;
}

} // namespace spicy::detail::pir::ir
