// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <cassert>
#include <memory>
#include <string>

#include <spicy/rt/global-state.h>

namespace spicy::rt {

/** Configuration parameters for the Spicy runtime system. */
struct Configuration {
    Configuration() {}

    using HookAcceptInput = void (*)();

    /**
     * Optional callback to execute when a Spicy parser calls
     * `spicy::accept_input()`.
     **/
    HookAcceptInput hook_accept_input = nullptr;

    using HookDeclineInput = void (*)(const std::string&);

    /**
     * Optional callback to execute when a Spicy parser calls
     * `spicy::decline_input()`. This string argument is the reason provided by
     * the caller.
     */
    HookDeclineInput hook_decline_input = nullptr;
};

namespace configuration {

namespace detail {

/**
 * Returns the current global configuration without checking if it's already
 * initialized. This is only safe to use if the runtime is already fully
 * initialized, and should be left to internal use only where performance
 * matters.
 */
inline const Configuration& unsafeGet() {
    assert(rt::detail::globalState()->configuration);
    return *rt::detail::globalState()->configuration;
}

} // namespace detail

/**
 * Returns the current global configuration. To change the
 * configuration, modify it and then pass it back to `set()`.
 */
inline const Configuration& get() {
    if ( ! rt::detail::globalState()->configuration )
        rt::detail::globalState()->configuration = std::make_unique<spicy::rt::Configuration>();

    return *rt::detail::globalState()->configuration;
}

/**
 * Sets new configuration values. Usually one first retrieves the current
 * configuration with `get()` to then apply any desired changes to it.
 *
 * @param cfg complete set of new configuration values
 */
extern void set(Configuration cfg);

} // namespace configuration
} // namespace spicy::rt
