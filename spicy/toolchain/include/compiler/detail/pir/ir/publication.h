// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <set>
#include <unordered_map>
#include <utility>
#include <vector>

#include <spicy/compiler/detail/pir/ir/package.h>

namespace spicy::detail::pir::ir {

/**
 * How one function publishes the fields of the units it creates, from a forward dataflow over its body. A unit value
 * descends from the `unit.create` that started it, through `unit.publish_field` results and Phis.
 */
struct Publications {
    /** The `unit.create` that each unit value descends from, by value index. A value of no known origin is absent. */
    std::unordered_map<uint32_t, InstId> origins;
    /** Phis whose Upsilons write units of more than one origin. */
    std::vector<InstId> mixed_phis;
    /** Publications of a field that some path to them has published already. */
    std::vector<InstId> duplicates;
    /** Each reachable `parser.finish`, with the fields published on every path to it. */
    std::vector<std::pair<InstId, std::set<uint32_t>>> finished;
};

/** Analyzes the publications of `function`. Unreachable blocks are ignored. */
Publications analyzePublications(const Package& package, FunctionId function);

} // namespace spicy::detail::pir::ir
