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
#if defined(_WIN32)
    __global_state->c_locale = _create_locale(LC_ALL, "C");
#else
    __global_state->c_locale = newlocale(LC_ALL_MASK, "C", nullptr);
#endif

    if ( ! __global_state->c_locale )
        fatalError("failed to create C locale");

    return __global_state;
}

GlobalState::~GlobalState() {
    HILTI_RT_DEBUG("libhilti", "destroying global state");

    if ( c_locale )
#if defined(_WIN32)
        _free_locale(*c_locale);
#else
        freelocale(*c_locale);
#endif
}
