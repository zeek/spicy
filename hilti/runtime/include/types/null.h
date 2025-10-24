// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <arpa/inet.h>

#include <ostream>
#include <string>

#include <hilti/rt/extension-points.h>

namespace hilti::rt {

template<typename T>
class Optional;

/**
 * Represents HILTI's "null" type.
 */
struct Null {
    template<typename T>
    operator hilti::rt::Optional<T>() {
        return {};
    }
};

namespace detail::adl {
inline std::string to_string(const Null& x, adl::tag /*unused*/) { return "Null"; }
} // namespace detail::adl

inline std::ostream& operator<<(std::ostream& out, const Null& x) { return out << "Null"; }

} // namespace hilti::rt
