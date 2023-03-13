// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <cstddef>
#include <iostream>
#include <optional>
#include <string>

#include <hilti/rt/filesystem.h>
#include <hilti/rt/util.h>

namespace hilti::rt {

/** Configuration parameters for the HILTI runtime system. */
struct Configuration {
    Configuration();

    /** Stack size for fibers with individual stacks. */
    size_t fiber_individual_stack_size = static_cast<size_t>(1 * 1024 * 1024);

    /** Stack size for shared fiber stack. */
    size_t fiber_shared_stack_size = static_cast<size_t>(1 * 1024 * 1024);

    /** Minimum size of a fiber's buffer for swapped out stack data. */
    size_t fiber_shared_stack_swap_size_min = static_cast<size_t>(2 * 1024);

    /** Max. number of fibers cached for reuse. */
    unsigned int fiber_cache_size = 100;

    /**
     * Minimum stack size that a fiber must have left for use at beginning of a
     * function's execution. This should leave enough headroom for (1) the
     * current function to still execute, and (2) safely abort with an
     * exception if we're getting too low. (It seems that the latter can
     * require quite a bit of space, hence the large default here.)
     **/
    size_t fiber_min_stack_size = static_cast<size_t>(20 * 1024);

    /** File where debug output is to be sent. Default is stderr. */
    std::optional<hilti::rt::filesystem::path> debug_out;

    /** Show backtraces when reporting unhandled exceptions. */
    bool show_backtraces = false;

    /** abort() instead of throwing HILTI exceptions. */
    bool abort_on_exceptions = false;

    /**< Print summary of runtime resource usage at termination. */
    bool report_resource_usage = false;

    /**< Enable execution profiler. This also requires compiling HILTI code with profiling instrumentation.  */
    bool enable_profiling = false;

    /** Colon-separated list of debug streams to enable. Default comes from HILTI_DEBUG. */
    std::string debug_streams;

    /** Output stream for hilti::print(). If unset, printing will be silenced. */
    std::optional<std::reference_wrapper<std::ostream>> cout;
};

namespace configuration {
/**
 * Returns the current global configuration. To change the
 * configuration, modify it and then pass it back to `set()`.
 */
extern const Configuration& get();

/**
 * Sets new configuration values. Usually one first retrieves the current
 * configuration with `get()` to then apply any desired changes to it.
 *
 * @param cfg complete set of new configuration values
 */
extern void set(Configuration cfg);

} // namespace configuration
} // namespace hilti::rt
