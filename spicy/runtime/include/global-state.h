// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace spicy::rt {
struct Parser;
} // namespace spicy::rt

// We collect all (or most) of the runtime's global state centrally. That's
// 1st good to see what we have (global state should be minimal) and 2nd
// helpful to ensure that JIT maps things correctly. Note that all code
// accessing any of this state is in charge of ensuring thread-safety itself.
// These globals are generally initialized through spicy::rt::init();

namespace spicy::rt::detail {

/** Struct capturing all truely global runtime state. */
struct GlobalState {
    GlobalState() = default;
    ~GlobalState();

    GlobalState(const GlobalState&) = delete;
    GlobalState(GlobalState&&) noexcept = delete;
    GlobalState& operator=(const GlobalState&) = delete;
    GlobalState& operator=(GlobalState&&) noexcept = delete;

    /** True once `hilit::init()`` has finished. */
    bool runtime_is_initialized = false;

    /**
     * List of available parsers. Compiled Spicy parsers register themselves
     * with this list automatically at initialization time.
     */
    std::vector<const Parser*> parsers;

    /** Default parser to use, if it can be determined. */
    std::optional<const Parser*> default_parser;

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

} // namespace spicy::rt::detail
