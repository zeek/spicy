// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/base/logger.h>
#include <hilti/rt/logging.h>

namespace spicy::zeek::debug {
// Backend for performing debug logging. Must be implemented by application
// using the functionality.
extern void do_log(const std::string_view& msg);
} // namespace spicy::zeek::debug

// Macro helper to report debug messages.
//
// This forwards to another function that must be implemeneted externally to
// do the actual logging. The function can decide where to send it to, which
// may, depending compilation mode, maybe the HILTI logger, the runtime's
// logger, or both.
#define ZEEK_DEBUG(msg) spicy::zeek::debug::do_log(msg);
