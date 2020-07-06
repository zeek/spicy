// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <clocale>

#include <hilti/rt/init.h>

#include <spicy/rt/global-state.h>
#include <spicy/rt/hilti-fwd.h>
#include <spicy/rt/init.h>
#include <spicy/rt/parser.h>

using namespace spicy::rt;
using namespace spicy::rt::detail;

void spicy::rt::init() {
    if ( globalState()->runtime_is_initialized )
        return;

    if ( ! hilti::rt::isInitialized() )
        fatalError("hilti::rt::init() must be called before spicy::rt::init()");

    HILTI_RT_DEBUG("libspicy", "initializing runtime");

    for ( const auto& p : globalState()->parsers )
        HILTI_RT_DEBUG("libspicy", fmt("registered parser %s", p->name));

    globalState()->runtime_is_initialized = true;
}

void spicy::rt::done() {
    if ( ! globalState() )
        return;

    HILTI_RT_DEBUG("libspicy", "shutting down runtime");

    delete __global_state; // NOLINT(cppcoreguidelines-owning-memory)
    __global_state = nullptr;
}

bool spicy::rt::isInitialized() { return globalState()->runtime_is_initialized; }
