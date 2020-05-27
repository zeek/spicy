// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <iostream>
#include <optional>

#include <hilti/rt/util.h>

namespace hilti::rt {

/** Configuration parameters for the HILTI runtime system. */
struct Configuration {
    Configuration();

    /** Stack size for fibers. */
    size_t fiber_stack_size = 100 * 1024 * 1024; // This is generous.

    /** Maximum size of pool of recycalable fibers. */
    size_t fiber_max_pool_size = 1000;

    /** File where debug output is to be sent. Default is stderr. */
    std::optional<std::filesystem::path> debug_out;

    /** Show backtraces when reporting unhandled exceptions. */
    bool show_backtraces = false;

    /** abort() instead of throwing HILTI exceptions. */
    bool abort_on_exceptions = false;

    /** Colon-separated list of debug streams to enable. Default comes from HILTI_DEBUG. */
    std::string debug_streams;

    /** Output stream for hilti::print(). If unset, printing will be silenced. */
    std::optional<std::reference_wrapper<std::ostream>> cout;
};

namespace configuration {
/**
 * Returns a copy of the current global configuration. To change the
 * configuration, modify it and then pass it back to `set()`.
 */
extern Configuration get();

/**
 * Sets new configuration values. Usually one first retrieves the current
 * configuration with `get()` to then apply any desired changes to it.
 *
 * @param cfg complete set of new confifuration values
 */
extern void set(Configuration cfg);

} // namespace configuration
} // namespace hilti::rt
