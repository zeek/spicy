// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string_view>

#include <hilti/rt/logging.h>

/** Records a debug message to the `spicy` debugging stream. */
#define SPICY_RT_DEBUG(msg) HILTI_RT_DEBUG("spicy", msg)

/** Records a debug message to the `spicy-verbose` debugging stream. */
#define SPICY_RT_DEBUG_VERBOSE(msg) HILTI_RT_DEBUG("spicy-verbose", msg)

namespace spicy::rt::debug {

using namespace hilti::rt::debug;

/** Returns true if verbose debug logging has been requested. */
inline bool wantVerbose() { return hilti::rt::debug::isEnabled("spicy-verbose"); }

} // namespace spicy::rt::debug
