// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <arpa/inet.h>

#include <string>
#include <variant>

#include <hilti/rt/extension-points.h>

namespace hilti::rt {

/**
 * Represents HILTI's "null" type.
 */
struct Null {};

namespace detail::adl {
inline std::string to_string(const Null& x, adl::tag /*unused*/) { return "Null"; }
} // namespace detail::adl

inline std::ostream& operator<<(std::ostream& out, const Null& x) {
    out << "Null";
    return out;
}

} // namespace hilti::rt
