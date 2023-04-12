// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <arpa/inet.h>

#include <optional>
#include <ostream>
#include <string>
#include <variant>

#include <hilti/rt/extension-points.h>

namespace hilti::rt {

/**
 * Represents HILTI's "null" type.
 */
struct Null {
    template<typename T>
    operator std::optional<T>() {
        return std::nullopt;
    }
};

namespace detail::adl {
inline std::string to_string(const Null& x, adl::tag /*unused*/) { return "Null"; }
} // namespace detail::adl

inline std::ostream& operator<<(std::ostream& out, const Null& x) { return out << "Null"; }

} // namespace hilti::rt
