// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include <hilti/rt/extension-points.h>
#include <hilti/rt/type-info.h>
#include <hilti/rt/types/tuple.h>
#include <hilti/rt/util.h>

namespace hilti::rt {

namespace trait {
struct isBitfield {};
} // namespace trait

/// A bitfield is just a type wrapper around a tuple of the corresponding field
/// values (including the hidden additional element storing the bitfield's
/// original integer value). We wrap it so that we can customize the
/// printing.
template<typename... Ts>
struct Bitfield : public trait::isBitfield {
    using value_type = Tuple<Ts...>;

    /** Construct a bitfield from a tuple. */
    Bitfield(value_type v = value_type()) : value(std::move(v)) {}

    /**
     * Support instantiation from another bitfield type as long as all types
     * convert over.
     */
    template<typename... Us>
    Bitfield(Bitfield<Us...> other) : value(std::move(other.value)) {}

    value_type value;
};

/// Construct a Bitfield.
///
/// Since a bitfield always owns its values this takes all fields by value.
template<typename... Ts>
Bitfield<Ts...> make_bitfield(Ts... args) {
    return {tuple::make(std::move(args)...)};
}

namespace bitfield {

template<typename Bitfield, size_t Idx>
ptrdiff_t elementOffset() {
    return tuple::elementOffset<decltype(Bitfield::value), Idx>();
}

namespace detail {

// Helper for the HILTI codegen to render a bitfield's value into a string.
template<typename... Ts>
inline std::string render(const Bitfield<Ts...>& x, const hilti::rt::TypeInfo* type_info, bool is_anonymous) {
    std::string out;

    type_info::Value bitfield(&x, type_info);
    for ( const auto& [b, v] : type_info->bitfield->iterate(bitfield) ) {
        if ( ! out.empty() )
            out += ", ";

        if ( is_anonymous )
            out += fmt("$%s=%s", b.name, v.to_string());
        else
            out += fmt("%s: %s", b.name, v.to_string());
    }

    return out;
}

// Helper for the HILTI codegen to render an optional bitfield value into a string.
template<typename... Ts>
inline std::string render(const std::optional<Bitfield<Ts...>>& x, const hilti::rt::TypeInfo* type_info,
                          bool is_anonymous = false) {
    if ( x.has_value() )
        return render(*x, type_info, is_anonymous);

    if ( ! is_anonymous )
        return fmt("(not set)");

    std::string out;

    Bitfield<Ts...> empty;
    type_info::Value bitfield(&empty, type_info);
    for ( const auto& [b, v] : type_info->bitfield->iterate(bitfield) ) {
        if ( ! out.empty() )
            out += ", ";

        out += fmt("$%s=(not set)", b.name);
    }

    return out;
}

} // namespace detail
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
