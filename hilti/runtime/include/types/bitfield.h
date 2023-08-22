// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include <hilti/rt/extension-points.h>
#include <hilti/rt/types/tuple.h>
#include <hilti/rt/util.h>

namespace hilti::rt {

/// A bitfield is just a type wrapper around a tuple of the corresponding field
/// values (including the hidden additional element storing the bitfield's
/// original integer value). We wrap it so that we can customize the
/// printing.
template<typename... Ts>
struct Bitfield {
    std::tuple<Ts...> value;
};

template<typename... Ts>
Bitfield<Ts...> make_bitfield(Ts&&... args) {
    return Bitfield<Ts...>{std::make_tuple(std::forward<Ts>(args)...)};
}

namespace bitfield {

template<typename Bitfield, size_t Idx>
ptrdiff_t elementOffset() {
    return tuple::elementOffset<decltype(Bitfield::value), Idx>();
}

} // namespace bitfield

// Helper to convert tuple to a vector of the elements' string representations.
// This version uses `to_string` for each element.
namespace detail {
template<class Tuple, class T = std::decay_t<std::tuple_element_t<0, std::decay_t<Tuple>>>>
std::vector<std::string> to_vector_with_to_string(Tuple&& tuple) {
    return std::apply(
        [](auto&&... elems) {
            std::vector<std::string> result;
            result.reserve(sizeof...(elems));
            (result.emplace_back(to_string(elems)), ...);
            return result;
        },
        std::forward<Tuple>(tuple));
}

// Helper to convert tuple to a vector of the elements' string representations.
// This version uses `to_string_for_print` for each element.
template<class Tuple, class T = std::decay_t<std::tuple_element_t<0, std::decay_t<Tuple>>>>
std::vector<std::string> to_vector_with_to_string_for_print(Tuple&& tuple) {
    return std::apply(
        [](auto&&... elems) {
            std::vector<std::string> result;
            result.reserve(sizeof...(elems));
            (result.emplace_back(to_string(elems)), ...);
            return result;
        },
        std::forward<Tuple>(tuple));
}
} // namespace detail

namespace detail::adl {
template<typename... Ts>
inline std::string to_string(const Bitfield<Ts...>& x, adl::tag /*unused*/) {
    // Need to remove the last, hidden element
    auto y = to_vector_with_to_string(x.value);
    y.pop_back();
    return fmt("(%s)", rt::join(std::move(y), ", "));
}

template<typename... Ts>
inline std::string to_string_for_print(const Bitfield<Ts...>& x, adl::tag /*unused*/) {
    // Need to remove the last, hidden element
    auto y = to_vector_with_to_string_for_print(x.value);
    y.pop_back();
    return fmt("(%s)", rt::join(std::move(y), ", "));
}
} // namespace detail::adl

} // namespace hilti::rt

namespace std {

template<typename... Ts>
inline std::ostream& operator<<(std::ostream& out, const hilti::rt::Bitfield<Ts...>& x) {
    return out << hilti::rt::to_string_for_print(x);
}

} // namespace std
