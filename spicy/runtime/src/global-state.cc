// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <spicy/rt/configuration.h>
#include <spicy/rt/debug.h>
#include <spicy/rt/global-state.h>
#include <spicy/rt/hilti-fwd.h>

using namespace spicy::rt;
using namespace spicy::rt::detail;

// Not memory-managed through smart pointer, need to control when we release it.
GlobalState* detail::__global_state = nullptr;

GlobalState* detail::createGlobalState() {
    __global_state = new GlobalState(); // NOLINT(cppcoreguidelines-owning-memory)
    return __global_state;
}

GlobalState::~GlobalState() { HILTI_RT_DEBUG("libspicy", "destroying global state"); }
