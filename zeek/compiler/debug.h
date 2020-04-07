// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/base/logger.h>
#include <hilti/rt/logging.h>

namespace spicy::zeek::debug {
extern const ::hilti::logging::DebugStream ZeekPlugin;
}

// Macro helper to send debug message both HILTI-side loggers: compiler and
// runtime.
//
// TODO(robin): Once we start using the Zeek compiler code outside of Zeek
// itself, we'll need to differentiate this further: We should then send the
// compiler's log message only to the HILTI logger intead (and not the HILTI
// runtime's logger).
#define ZEEK_DEBUG(msg)                                                                                                \
    {                                                                                                                  \
        HILTI_RT_DEBUG("zeek", msg);                                                                                   \
        HILTI_DEBUG(::spicy::zeek::debug::ZeekPlugin, msg);                                                            \
    }
