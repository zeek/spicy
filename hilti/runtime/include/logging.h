// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <utility>

#include <hilti/rt/debug-logger.h>
#include <hilti/rt/global-state.h>
#include <hilti/rt/types/string.h>
#include <hilti/rt/util.h>

namespace hilti::rt {

/**
 * Reports a fatal error and immediately aborts execution. This skips all
 * cleanup and should be used only for catastrophic library issues; not for
 * anything that can happen during "normal" operation (which is almost
 * everything).
 */
void fatalError(const std::string& msg) __attribute__((noreturn));

/** Reports a warning. */
void warning(const std::string& msg);

/**
 * Prints a string, or a runtime value, to a specific debug stream. This is a
 * macro wrapper around `debug::detail::print(*)` that avoids evaluation of
 * the arguments if nothing is going to get logged.
 */
#define HILTI_RT_DEBUG(stream, msg)                                                                                    \
    {                                                                                                                  \
        if ( ::hilti::rt::detail::unsafeGlobalState()->debug_logger &&                                                 \
             ::hilti::rt::detail::unsafeGlobalState()->debug_logger->isEnabled(stream) )                               \
            ::hilti::rt::debug::detail::print(stream, msg);                                                            \
    }

/** Shortcut to `hilti::rt::debug::setLocation`. */
#define __location__(x) ::hilti::rt::debug::detail::tls_location = x;

namespace debug {

namespace detail {
/** Prints a debug message to a specific debug stream. */
inline void print(const std::string& stream, const char* msg) {
    if ( ::hilti::rt::detail::globalState()->debug_logger )
        ::hilti::rt::detail::globalState()->debug_logger->print(stream, msg);
}

/** Print a string to a specific debug stream with proper escaping. */
inline void print(const std::string& stream, const std::string_view& s) {
    if ( ::hilti::rt::detail::globalState()->debug_logger )
        ::hilti::rt::detail::globalState()->debug_logger->print(stream, hilti::rt::escapeBytes(s, false));
}

template<typename T, typename std::enable_if_t<not std::is_convertible<T, std::string_view>::value>* = nullptr>
/** Prints the string representastion of a HILTI runtime value to a specific debug stream. */
inline void print(const std::string& stream, const T& t) {
    if ( ::hilti::rt::detail::globalState()->debug_logger )
        ::hilti::rt::detail::globalState()->debug_logger->print(stream, hilti::rt::to_string_for_print(t));
}
} // namespace detail

/** Returns true if debug logging is enabled for a given stream. */
inline bool isEnabled(const std::string& stream) {
    return ::hilti::rt::detail::globalState()->debug_logger &&
           ::hilti::rt::detail::globalState()->debug_logger->isEnabled(stream);
}

/** Increases the indentation level for a debug stream. */
inline void indent(const std::string& stream) {
    if ( ::hilti::rt::detail::globalState()->debug_logger )
        ::hilti::rt::detail::globalState()->debug_logger->indent(stream);
}

/** Decreases the indentation level for a debug stream. */
inline void dedent(const std::string& stream) {
    if ( ::hilti::rt::detail::globalState()->debug_logger )
        ::hilti::rt::detail::globalState()->debug_logger->dedent(stream);
}

namespace detail {
// Stores pointer to a string containing the current HILTI-side source
// location. This needs to be thread-local but also should also be as cheap as
// possible for updating the value.
extern HILTI_THREAD_LOCAL const char* tls_location;
} // namespace detail

/**
 * Returns the current source code location if set, or null if not.
 */
inline const char* location() { return detail::tls_location; }

/**
 * Sets the current source code location or unsets it if no argument.
 * *loc* must point to a static string that won't go out of scope.
 */
inline void setLocation(const char* l = nullptr) { detail::tls_location = l; }

/**
 * Prints a string, or a runtime value, to a specific debug stream. This is a
 * wrapper around `debug::detail::print(*)` that avoids evaluation of the
 * arguments if nothing is going to get logged.
 */
template<typename T>
inline void print(const std::string& stream, T&& msg) {
    if ( ::hilti::rt::detail::globalState()->debug_logger &&
         ::hilti::rt::detail::globalState()->debug_logger->isEnabled(stream) )
        ::hilti::rt::debug::detail::print(stream, std::forward<T>(msg));
}

} // namespace debug
} // namespace hilti::rt
