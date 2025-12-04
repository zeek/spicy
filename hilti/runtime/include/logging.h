// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <string_view>
#include <utility>

#include <hilti/rt/debug-logger.h>
#include <hilti/rt/global-state.h>
#include <hilti/rt/types/string.h>
#include <hilti/rt/util.h>

namespace hilti::rt {

struct TypeInfo;

/**
 * Reports a fatal error and immediately aborts execution. This skips all
 * cleanup and should be used only for catastrophic library issues; not for
 * anything that can happen during "normal" operation (which is almost
 * everything).
 */
void fatalError(std::string_view msg) __attribute__((noreturn));

/** Reports a warning. */
void warning(std::string_view msg);

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

namespace debug {

namespace detail {
/** Prints a debug message to a specific debug stream. */
inline void print(std::string_view stream, const char* msg) {
    if ( ::hilti::rt::detail::globalState()->debug_logger )
        ::hilti::rt::detail::globalState()->debug_logger->print(stream, msg);
}

/** Print a string to a specific debug stream with proper escaping. */
inline void print(std::string_view stream, std::string_view s) {
    if ( ::hilti::rt::detail::globalState()->debug_logger )
        ::hilti::rt::detail::globalState()->debug_logger->print(stream, hilti::rt::escapeBytes(s));
}

template<typename T>
/** Prints the string representation of a HILTI runtime value to a specific debug stream. */
inline void print(std::string_view stream, const T& t)
    requires(! std::is_convertible_v<T, std::string_view>)
{
    if ( ::hilti::rt::detail::globalState()->debug_logger )
        ::hilti::rt::detail::globalState()->debug_logger->print(stream, hilti::rt::to_string_for_print(t));
}
} // namespace detail

/** Returns true if debug logging is enabled for a given stream. */
inline bool isEnabled(std::string_view stream) {
    return ::hilti::rt::detail::globalState()->debug_logger &&
           ::hilti::rt::detail::globalState()->debug_logger->isEnabled(stream);
}

/** Increases the indentation level for a debug stream. */
inline void indent(std::string_view stream) {
    if ( ::hilti::rt::detail::globalState()->debug_logger )
        ::hilti::rt::detail::globalState()->debug_logger->indent(stream);
}

/** Decreases the indentation level for a debug stream. */
inline void dedent(const std::string_view stream) {
    if ( ::hilti::rt::detail::globalState()->debug_logger )
        ::hilti::rt::detail::globalState()->debug_logger->dedent(stream);
}

/**
 * Returns the current source code location if set, or null if not.
 */
inline const char* location() {
    if ( auto* ctx = ::hilti::rt::context::detail::current() ) {
        if ( auto* r = ctx->resumable )
            return r->location();
        else
            return ctx->location;
    }
    else
        return nullptr;
}

/**
 * Sets the current source code location, or unsets it if argument is null.
 *
 * @param l pointer to a statically allocated string that won't go out of scope.
 */
inline void setLocation(const char* l = nullptr) {
    if ( auto* ctx = ::hilti::rt::context::detail::current() ) {
        if ( auto* r = ctx->resumable )
            r->setLocation(l);
        else
            ctx->location = l;
    }
}

/**
 * Prints a string, or a runtime value, to a specific debug stream. This is a
 * wrapper around `debug::detail::print(*)` that avoids evaluation of the
 * arguments if nothing is going to get logged.
 */
template<typename T>
inline void print(std::string_view stream, T&& msg, const TypeInfo* /* type */) {
    if ( ::hilti::rt::detail::globalState()->debug_logger &&
         ::hilti::rt::detail::globalState()->debug_logger->isEnabled(stream) )
        ::hilti::rt::debug::detail::print(stream, std::forward<T>(msg));
}

} // namespace debug

/** Shortcut to `hilti::rt::debug::setLocation`. */
inline void location(const char* x) { hilti::rt::debug::setLocation(x); }

} // namespace hilti::rt
