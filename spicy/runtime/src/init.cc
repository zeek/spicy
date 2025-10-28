// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <hilti/rt/init.h>

#include <spicy/rt/configuration.h>
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

    // Force lazy initialization of Spicy runtime configuration.
    configuration::get();

    HILTI_RT_DEBUG("libspicy", "initializing runtime");

    auto& parsers = globalState()->parsers;

    hilti::rt::Optional<const Parser*> default_parser;

    for ( const auto& p : parsers ) {
        if ( p->is_public ) {
            if ( ! default_parser.hasValue() )
                default_parser = p;
            else
                default_parser = hilti::rt::Null();
        }

        globalState()->parsers_by_name[{p->name.data(), p->name.size()}].emplace_back(p);

        for ( const auto& x : p->ports ) {
            auto idx = std::string(x.port);

            switch ( x.direction.value() ) {
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

    globalState()->default_parser = default_parser;

    HILTI_RT_DEBUG("libspicy", "registered parsers (w/ aliases):");
    for ( const auto& i : globalState()->parsers_by_name ) {
        auto names = hilti::rt::transform(i.second, [](const auto& p) {
            return fmt("%s (scope 0x%" PRIx64 ")", p->name, p->linker_scope);
        });
        HILTI_RT_DEBUG("libspicy", hilti::rt::fmt("  %s -> %s", i.first, hilti::rt::join(names, ", ")));
    }

    HILTI_RT_DEBUG("libspicy", "registered parsers for MIME types:");
    for ( const auto& i : globalState()->parsers_by_mime_type ) {
        auto names = hilti::rt::transform(i.second, [](const auto& p) {
            return fmt("%s (scope 0x%" PRIx64 ")", p->name, p->linker_scope);
        });
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
