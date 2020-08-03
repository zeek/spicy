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

    auto& parsers = globalState()->parsers;

    if ( parsers.size() == 1 )
        globalState()->default_parser = parsers.front();

    for ( const auto& p : parsers ) {
        globalState()->parsers_by_name[p->name].emplace_back(p);

        for ( const auto& x : p->ports )
            globalState()->parsers_by_name[x].emplace_back(p);

        for ( const auto& x : p->mime_types ) {
            if ( ! x.isWildcard() )
                globalState()->parsers_by_name[x].emplace_back(p);
        }
    }

    HILTI_RT_DEBUG("libspicy", "registered parsers (w/ aliases):");
    for ( const auto& i : globalState()->parsers_by_name ) {
        auto names = hilti::rt::transform(i.second, [](const auto& p) { return p->name; });
        HILTI_RT_DEBUG("libspicy", hilti::rt::fmt("  %s -> %s", i.first, hilti::rt::join(names, ", ")));
    }

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
