// Copyright (c) 2020-2024 by the Zeek Project. See LICENSE for details.
//
// This code is copied and adapted from Broker, Zeek's communication framework.
// The original version can be found at
// https://github.com/zeek/broker/blob/master/libbroker/broker/detail/monotonic_buffer_resource.cc
//
// Functional changes:
//     - Different from Broker, we *do* follow a geometric progression, just like the std version.

#include <algorithm>
#include <cstdlib>
#include <memory>

#include <hilti/base/monotonic_buffer_resource.h>

using namespace hilti::detail;

void* monotonic_buffer_resource::allocate(size_t num_bytes, size_t alignment) {
    auto res = std::align(alignment, num_bytes, current_->bytes, remaining_);
    if ( res == nullptr ) {
        allocate_block(current_, num_bytes);
        res = std::align(alignment, num_bytes, current_->bytes, remaining_);
        if ( res == nullptr )
            throw std::bad_alloc();
    }
    current_->bytes = static_cast<std::byte*>(res) + num_bytes;
    remaining_ -= num_bytes;
    return res;
}

void monotonic_buffer_resource::allocate_block(block* prev_block, size_t min_size) {
    // [Spicy] Grow by 1.5x.
    auto size = std::max(static_cast<size_t>(previous_size_ * 15 / 10), min_size + sizeof(block) + sizeof(max_align_t));
    if ( auto vptr = malloc(size) ) {
        current_ = static_cast<block*>(vptr);
        current_->next = prev_block;
        current_->bytes = static_cast<std::byte*>(vptr) + sizeof(block);
        remaining_ = size - sizeof(block);
        previous_size_ = size;
    }
    else {
        throw std::bad_alloc();
    }
}

void monotonic_buffer_resource::destroy() noexcept {
    auto blk = current_;
    while ( blk != nullptr ) {
        auto prev = blk;
        blk = blk->next;
        free(prev);
    }
}
