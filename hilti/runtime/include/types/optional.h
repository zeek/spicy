// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <optional>
#include <string>

#include <hilti/rt/extension-points.h>

namespace hilti::rt {

template<typename T>
using Optional = std::optional<T>;

namespace detail::adl {
template<typename T>
inline std::string to_string(const Optional<T>& x, adl::tag /*unused*/) {
    return x ? hilti::rt::to_string(*x) : "(not set)";
}

} // namespace detail::adl

namespace optional {

struct Unset : public std::exception {}; // Internal exception to signal access to optional that may expectedly by unset

namespace detail {
extern __attribute__((noreturn)) void throw_unset();
extern __attribute__((noreturn)) void throw_unset_optional();
} // namespace detail

template<class T>
constexpr std::optional<std::decay_t<T>> make(T&& v) {
    return std::optional<std::decay_t<T>>(std::forward<T>(v));
}

template<class T, class... Args>
constexpr std::optional<T> make(Args&&... args) {
    return std::optional<T>(std::in_place, std::forward<Args>(args)...);
}

template<class T>
inline auto& value(const Optional<T>& t) {
    if ( t.has_value() )
        return t.value();
    else
        detail::throw_unset_optional();
}

template<class T>
inline auto& value(Optional<T>& t) {
    if ( t.has_value() )
        return t.value();
    else
        detail::throw_unset_optional();
}

template<class T>
inline auto& valueOrInit(Optional<T>& t, const T& default_) {
    if ( ! t.has_value() )
        t = default_;

    return t.value();
}

template<class T>
inline auto& valueOrInit(Optional<T>& t) {
    if ( ! t.has_value() )
        t.emplace();

    return t.value();
}

template<class T>
inline auto& tryValue(const Optional<T>& t) {
    if ( t.has_value() )
        return t.value();
    else
        detail::throw_unset();
}

} // namespace optional

template<>
inline std::string detail::to_string_for_print<Optional<std::string>>(const Optional<std::string>& x) {
    return x ? *x : "(not set)";
}

template<>
inline std::string detail::to_string_for_print<Optional<std::string_view>>(const Optional<std::string_view>& x) {
    return x ? std::string(*x) : "(not set)";
}

} // namespace hilti::rt

namespace std {

// Provide operator<< overload for optionals that have a custom HILTI-side to_string() conversion.
template<typename T>
inline auto operator<<(std::ostream& out, const hilti::rt::Optional<T>& x)
    -> decltype(::hilti::rt::detail::adl::to_string(x, ::hilti::rt::detail::adl::tag()), out) {
    out << ::hilti::rt::to_string(x);
    return out;
}

} // namespace std
