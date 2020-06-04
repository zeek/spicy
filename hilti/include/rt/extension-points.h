// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <utility>

namespace hilti::rt {

// See https://stackoverflow.com/questions/28070519/customization-points-and-adl.
namespace detail::adl {
struct tag {};

#if __GNUC__
// TODO(robin): gcc9 doesn't allow to delete these, not sure why. Using
// externs instead, without implementation.
extern std::string to_string();
extern void safe_begin();
extern void safe_end();
#else
std::string to_string() = delete;
void safe_begin() = delete;
void safe_end() = delete;
#endif

} // namespace detail::adl

/** Converts a HILTI runtime type into a string representation. */
template<typename T>
std::string to_string(T&& x) {
    using detail::adl::to_string;
    return to_string(std::forward<T>(x), detail::adl::tag{});
}

/**
 * Returns a "safe" container start iterator. "safe" refers to the HILTI
 * model: Accessing a safe iterator when the underlying container went away
 * will be caught through an exception (rather than a crash).
 */
template<typename T>
auto safe_begin(const T& x) {
    using detail::adl::safe_begin;
    return safe_begin(x, detail::adl::tag{});
}
template<typename T>
auto safe_begin(T& x) {
    using detail::adl::safe_begin;
    return safe_begin(x, detail::adl::tag{});
}

/**
 * Returns a "safe" container end iterator. "safe" refers to the HILTI model:
 * Accessing a safe iterator when the underlying container went away will be
 * caught through an exception (rather than a crash).
 */
template<typename T>
auto safe_end(const T& x) {
    using detail::adl::safe_end;
    return safe_end(x, detail::adl::tag{});
}
template<typename T>
auto safe_end(T& x) {
    using detail::adl::safe_end;
    return safe_end(x, detail::adl::tag{});
}

namespace detail {
template<typename T>
inline std::string to_string_for_print(const T& x) {
    return hilti::rt::to_string(x);
}
} // namespace detail

/**
 * Converts a HILTI runtime type into the string representation that
 * `hilti::print()` outputs. This representastion is slightly different from
 * the standard one (e.g., it doesn't enclose top-level strings in quotation
 * marks).
 */
template<typename T>
inline std::string to_string_for_print(const T& x) {
    return detail::to_string_for_print(x);
}

} // namespace hilti::rt
