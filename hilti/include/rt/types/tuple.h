// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/rt/extension-points.h>
#include <hilti/rt/util.h>

namespace hilti::rt {

namespace detail::adl {
template<typename T, typename std::enable_if_t<is_tuple<T>::value>* = nullptr>
inline std::string to_string(const T& x, adl::tag /*unused*/) {
    auto y = rt::map_tuple(x, [&](auto& v) { return hilti::rt::to_string(v); });
    return fmt("(%s)", rt::join_tuple_for_print(std::move(y)));
}

template<typename T, typename std::enable_if_t<is_tuple<T>::value>* = nullptr>
inline std::string to_string_for_print(const T& x, adl::tag /*unused*/) {
    auto y = rt::map_tuple(x, [&](auto& v) { return hilti::rt::to_string(v); });
    return fmt("(%s)", rt::join_tuple_for_print(std::move(y)));
}
} // namespace detail::adl

} // namespace hilti::rt

template<typename T, typename std::enable_if_t<hilti::rt::is_tuple<T>::value>* = nullptr>
inline std::ostream& operator<<(std::ostream& out, const T& x) {
    return out << hilti::rt::to_string_for_print(x);
}
