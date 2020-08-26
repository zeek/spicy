// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <clocale>
#include <optional>

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
    else
        globalState()->default_parser = std::nullopt;

    for ( const auto& p : parsers ) {
        globalState()->parsers_by_name[p->name].emplace_back(p);

        for ( const auto& x : p->ports ) {
            auto idx = std::string(x.port);

            switch ( x.direction ) {
                case Direction::Originator: globalState()->parsers_by_name[idx + "%orig"].emplace_back(p); break;

                case Direction::Responder: globalState()->parsers_by_name[idx + "%resp"].emplace_back(p); break;

                case Direction::Both:
                    globalState()->parsers_by_name[idx].emplace_back(p);
                    globalState()->parsers_by_name[idx + "%orig"].emplace_back(p);
                    globalState()->parsers_by_name[idx + "%resp"].emplace_back(p);
                    break;

                case Direction::Undef: break;
            }
        }

        for ( const auto& mt : p->mime_types ) {
            if ( ! mt.isWildcard() )
                globalState()->parsers_by_name[mt].push_back(p);

            globalState()->parsers_by_mime_type[mt.asKey()].push_back(p);
        }
    }

    HILTI_RT_DEBUG("libspicy", "registered parsers (w/ aliases):");
    for ( const auto& i : globalState()->parsers_by_name ) {
        auto names = hilti::rt::transform(i.second, [](const auto& p) { return p->name; });
        HILTI_RT_DEBUG("libspicy", hilti::rt::fmt("  %s -> %s", i.first, hilti::rt::join(names, ", ")));
    }

    HILTI_RT_DEBUG("libspicy", "registered parsers for MIME types:");
    for ( const auto& i : globalState()->parsers_by_mime_type ) {
        auto names = hilti::rt::transform(i.second, [](const auto& p) { return p->name; });
        HILTI_RT_DEBUG("libspicy", hilti::rt::fmt("  %s -> %s", i.first, hilti::rt::join(names, ", ")));
    }

    globalState()->runtime_is_initialized = true;
}

void spicy::rt::done() {
    if ( ! __global_state )
        return;

    HILTI_RT_DEBUG("libspicy", "shutting down runtime");

    delete __global_state; // NOLINT(cppcoreguidelines-owning-memory)
    __global_state = nullptr;
}

bool spicy::rt::isInitialized() { return detail::__global_state && detail::__global_state->runtime_is_initialized; }
