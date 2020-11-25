// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <fiber/fiber.h>

#include <hilti/rt/configuration.h>
#include <hilti/rt/context.h>
#include <hilti/rt/global-state.h>
#include <hilti/rt/logging.h>

using namespace hilti::rt;
using namespace hilti::rt::detail;

// Not memory-managed through smart pointer, need to control when we release
// it.
GlobalState* detail::__global_state = nullptr;

GlobalState* detail::createGlobalState() {
    __global_state = new GlobalState(); // NOLINT (cppcoreguidelines-owning-memory)
    return __global_state;
}

GlobalState::~GlobalState() {
    HILTI_RT_DEBUG("libhilti", "destroying global state");

    if ( fiber_switch_trampoline )
        ::fiber_destroy(fiber_switch_trampoline.get());
}
