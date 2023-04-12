// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <functional>
#include <optional>
#include <string>

namespace spicy::rt {

/** Configuration parameters for the Spicy runtime system. */
struct Configuration {
    Configuration() {}

    /**
     * Optional callback to execute when a Spicy parser calls
     * `spicy::accept_input()`.
     **/
    std::optional<std::function<void()>> hook_accept_input;

    /**
     * Optional callback to execute when a Spicy parser calls
     * `spicy::decline_input()`. This string argument is the reason provided by
     * the caller.
     */
    std::optional<std::function<void(const std::string&)>> hook_decline_input;
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
} // namespace spicy::rt
