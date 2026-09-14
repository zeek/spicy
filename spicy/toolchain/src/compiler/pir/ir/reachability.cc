// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <spicy/compiler/detail/pir/ir/reachability.h>

namespace spicy::detail::pir::ir {

ReachableIds computeReachableIds(const Package& package) {
    ReachableIds reach;

    for ( const auto& fn : package.functions() ) {
        if ( ! package.isValid(fn.root_region) )
            continue;

        if ( ! reach.regions.insert(fn.root_region.index).second ) {
            reach.duplicate_regions.push_back(fn.root_region);
            continue;
        }

        for ( auto block_id : package.region(fn.root_region).blocks ) {
            if ( ! package.isValid(block_id) )
                continue;

            if ( ! reach.blocks.insert(block_id.index).second ) {
                reach.duplicate_blocks.push_back(block_id);
                continue;
            }

            for ( auto inst_id : package.block(block_id).insts ) {
                if ( ! package.isValid(inst_id) )
                    continue;

                if ( ! reach.insts.insert(inst_id.index).second )
                    reach.duplicate_insts.push_back(inst_id);
            }
        }
    }

    return reach;
}

} // namespace spicy::detail::pir::ir
