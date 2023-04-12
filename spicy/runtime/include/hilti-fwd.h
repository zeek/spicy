// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <utility>

#include <hilti/rt/fmt.h>
#include <hilti/rt/logging.h>
#include <hilti/rt/util.h>

namespace spicy::rt {

/** sprintf-style string formatting. */
template<typename... Args>
auto fmt(const std::string& s, const Args&... args) {
    return hilti::rt::fmt(s, args...);
}

/**
 * Reports an internal error and aborts execution.
 *
 * @note This forwards to the corresponding HILTI runtime function.
 */
inline void internalError(const std::string& msg) { hilti::rt::internalError(msg); }

/**
 * Reports an fatal error and aborts execution.
 *
 * @note This forwards to the corresponding HILTI runtime function.
 */
inline void fatalError(const std::string& msg) { hilti::rt::fatalError(msg); }

} // namespace spicy::rt
