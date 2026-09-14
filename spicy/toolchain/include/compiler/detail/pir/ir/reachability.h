// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <unordered_set>
#include <vector>

#include <spicy/compiler/detail/pir/ir/package.h>

namespace spicy::detail::pir::ir {

struct ReachableIds {
    std::unordered_set<uint32_t> regions;
    std::unordered_set<uint32_t> blocks;
    std::unordered_set<uint32_t> insts;

    std::vector<RegionId> duplicate_regions;
    std::vector<BlockId> duplicate_blocks;
    std::vector<InstId> duplicate_insts;
};

ReachableIds computeReachableIds(const Package& package);

} // namespace spicy::detail::pir::ir
