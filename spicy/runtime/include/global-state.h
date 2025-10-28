// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <cassert>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include <hilti/rt/types/optional.h>

namespace spicy::rt {
struct Parser;
struct Configuration;
} // namespace spicy::rt

// We collect all (or most) of the runtime's global state centrally. That's
// 1st good to see what we have (global state should be minimal) and 2nd
// helpful to ensure that JIT maps things correctly. Note that all code
// accessing any of this state is in charge of ensuring thread-safety itself.
// These globals are generally initialized through spicy::rt::init();

namespace spicy::rt::detail {

/** Struct capturing all truly global runtime state. */
struct GlobalState {
    GlobalState() = default;
    ~GlobalState();

    GlobalState(const GlobalState&) = delete;
    GlobalState(GlobalState&&) noexcept = delete;
    GlobalState& operator=(const GlobalState&) = delete;
    GlobalState& operator=(GlobalState&&) noexcept = delete;

    /** True once `hilit::init()`` has finished. */
    bool runtime_is_initialized = false;

    /** The runtime's configuration. */
    std::unique_ptr<Configuration> configuration;

    /**
     * List of available parsers. Compiled Spicy parsers register themselves
     * with this list automatically at initialization time.
     */
    std::vector<const Parser*> parsers;

    /** Default parser to use, if it can be determined. */
    hilti::rt::Optional<const Parser*> default_parser;

    /**
     * Map of parsers by all their possible names. This includes port and
     * MIME type specifications as supported by `spicy-driver -p <name>``.
     */
    std::map<std::string, std::vector<const Parser*>> parsers_by_name;

    /** Map of parsers by the MIME types they handle. */
    std::map<std::string, std::vector<const Parser*>> parsers_by_mime_type;
};

/**
 * Pointer to the global state singleton. Do not access directly, use
 * `globalState()` instead.
 */
extern GlobalState* __global_state;

/** Creates the global state singleton. */
extern GlobalState* createGlobalState();

/**
 * Returns the global state singleton. This creates the state the first time
 * it's called.
 */
inline auto globalState() {
    if ( __global_state )
        return __global_state;

    return createGlobalState();
}

/**
 * Returns the current global configuration without checking if it's already
 * initialized. This is only safe to use if the runtime is already fully
 * initialized, and should be left to internal use only where performance
 * matters.
 */
inline const GlobalState* unsafeGlobalState() {
    assert(__global_state);
    return __global_state;
}

} // namespace spicy::rt::detail
