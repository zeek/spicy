// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <utility>

namespace hilti::rt {

// See https://stackoverflow.com/questions/28070519/customization-points-and-adl.
namespace detail::adl {
struct tag {};

#if __GNUC__
// TODO(robin): gcc9 doesn't allow to delete these, not sure why. Using
// extern instead, without implementation.
extern std::string to_string();
#else
std::string to_string() = delete;
#endif

} // namespace detail::adl

/** Converts a HILTI runtime type into a string representation. */
template<typename T>
std::string to_string(T&& x) {
    using detail::adl::to_string;
    return to_string(std::forward<T>(x), detail::adl::tag{});
}

namespace detail {
template<typename T>
inline std::string to_string_for_print(const T& x) {
    return hilti::rt::to_string(x);
}
} // namespace detail

/**
 * Converts a HILTI runtime type into the string representation that
 * `hilti::print()` outputs. This representation is slightly different from
 * the standard one (e.g., it doesn't enclose top-level strings in quotation
 * marks).
 */
template<typename T>
inline std::string to_string_for_print(const T& x) {
    return detail::to_string_for_print(x);
}

} // namespace hilti::rt
