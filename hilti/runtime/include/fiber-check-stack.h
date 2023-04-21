// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.
//
// Split out from fiber.h to avoid circular dependencies.

#pragma once

#include <cstdint>

#include <hilti/rt/context.h>

namespace hilti::rt::detail {

/** Helper recording global stack resource usage. */
extern void trackStack();

/**
 * Checks that the current fiber has sufficient stack space left for executing
 * a function body. This is called often and should reduce overhead as much as
 * possible.
 *
 * \throws StackSizeExceeded if the minimum size is not available
 */
inline void checkStack() {
    static uint64_t cnt = 0;

    // Check stack only every other time, to reduce overhead.
    if ( ++cnt % 2 != 0 )
        return;

    if ( context::detail::get()->fiber.current->stackBuffer().liveRemainingSize() <
         ::hilti::rt::configuration::detail::unsafeGet().fiber_min_stack_size )
        throw StackSizeExceeded("not enough stack space remaining");

    // Do additional book-keeping every 8th time.
    if ( cnt % 8 == 0 )
        trackStack();
}

} // namespace hilti::rt::detail
