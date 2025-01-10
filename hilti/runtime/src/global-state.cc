// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

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
    __global_state->c_locale = newlocale(LC_ALL_MASK, "C", nullptr);

    if ( ! __global_state->c_locale )
        fatalError("failed to create C locale");

    return __global_state;
}

GlobalState::~GlobalState() {
    HILTI_RT_DEBUG("libhilti", "destroying global state");

    if ( c_locale )
        freelocale(*c_locale);
}
