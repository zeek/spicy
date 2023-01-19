// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

namespace spicy::rt {

/** Configuration parameters for the Spicy runtime system. */
struct Configuration {
    Configuration(){};
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
