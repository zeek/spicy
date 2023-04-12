// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

namespace spicy::rt {

/**
 * Initializes the Spicy runtime library. This must be called once at
 * startup before any other libspicy functionality can be used.
 */
extern void init();

/**
 * Shuts down the runtime library, freeing all resources. Once executed, no
 * libspicy functionality can be used anymore.
 */
extern void done();

/** Returns true if init() has already been called. */
extern bool isInitialized();

} // namespace spicy::rt
