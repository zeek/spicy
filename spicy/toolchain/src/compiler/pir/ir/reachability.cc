// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <spicy/compiler/detail/pir/ir/reachability.h>

namespace spicy::detail::pir::ir {

ReachableIds computeReachableIds(const Package& package) {
    ReachableIds reach;

    auto walk_region = [&](auto&& self, RegionId region_id) -> void {
        if ( ! package.isValid(region_id) )
            return;
        if ( ! reach.regions.insert(region_id.index).second ) {
            reach.duplicate_regions.push_back(region_id);
            return;
        }

        for ( auto block_id : package.region(region_id).blocks ) {
            if ( ! package.isValid(block_id) )
                continue;
            if ( ! reach.blocks.insert(block_id.index).second ) {
                reach.duplicate_blocks.push_back(block_id);
                continue;
            }
            for ( auto inst_id : package.block(block_id).insts ) {
                if ( ! package.isValid(inst_id) )
                    continue;
                if ( ! reach.insts.insert(inst_id.index).second ) {
                    reach.duplicate_insts.push_back(inst_id);
                    continue;
                }
                for ( auto child : package.inst(inst_id).regions )
                    self(self, child);
            }
        }
    };

    for ( const auto& fn : package.functions() ) {
        if ( ! package.isValid(fn.root_region) )
            continue;

        walk_region(walk_region, fn.root_region);
    }

    return reach;
}

} // namespace spicy::detail::pir::ir
