// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

/**
 * Wrappers around Zeek's reporter functionality to decouple from that
 * implementation.
 */

#pragma once

#include <compiler/debug.h>
#include <stdlib.h>

#include <string>

#include "plugin.h"

namespace spicy::zeek::reporter {

namespace detail {
// For ZEEK_DEBUG
inline const char* to_char_ptr(const char* p) { return p; }
inline const char* to_char_ptr(const std::string& p) { return p.c_str(); }
} // namespace detail

/** Reports an error through the Zeek reporter. */
extern void error(const std::string& msg);

/** Reports an fatal error through the Zeek reporter, aborting execution. */
extern void fatalError(const std::string& msg);

/** Reports an warning through the Zeek reporter. */
extern void warning(const std::string& msg);

/** Reports an internal error through the Zeek reporter, aborting execution. */
extern void internalError(const std::string& msg);

/** Reports a connection-associated "weird" through the Zeek reporter. */
extern void weird(::zeek::Connection* conn, const std::string& msg);

/** Reports a file-associated "weird" through the Zeek reporter. */
extern void weird(::zeek::file_analysis::File* f, const std::string& msg);

/** Reports a generic "weird" through the Zeek reporter. */
extern void weird(const std::string& msg);

/** Report an error and disable a protocol analyzer's input processing */
void analyzerError(::zeek::analyzer::Analyzer* a, const std::string& msg, const std::string& location);

/** Report an error and disable a file analyzer's input processing */
void analyzerError(::zeek::file_analysis::Analyzer* a, const std::string& msg, const std::string& location);

#ifdef HAVE_PACKET_ANALYZERS
/** Report an error and disable a packet analyzer's input processing. */
void analyzerError(::zeek::packet_analysis::Analyzer* a, const std::string& msg, const std::string& location);
#endif

/** Returns the number of errors recorded by the Zeek reporter. */
extern int numberErrors();

} // namespace spicy::zeek::reporter
