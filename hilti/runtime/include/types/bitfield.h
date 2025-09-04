// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <tuple>
#include <utility>

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
    Bitfield(value_type v, const hilti::rt::TypeInfo* ti) : value(std::move(v)), ti(ti) {}

    /** Construct an entirely unset bitfield. */
    Bitfield(const hilti::rt::TypeInfo* ti = nullptr) : ti(ti) {}

    /**
     * Support instantiation from another bitfield type as long as all types
     * convert over.
     */
    template<typename... Us>
    Bitfield(Bitfield<Us...> other) : value(std::move(other.value)), ti(other.ti) {}

    /**
     * Returns the binary offset of a particular bit range inside the
     * bitfield's storage. The offset refers is to the start of the bitfield.
     *
     * @tparam Idx index of the bit range to return
     */
    template<size_t Idx>
    static ptrdiff_t elementOffset() {
        return value_type::template elementOffset<Idx>();
    }

    value_type value = value_type();
    const hilti::rt::TypeInfo* ti;
};

/// Construct a Bitfield.
///
/// Since a bitfield always owns its values this takes all fields by value.
template<typename... Ts>
Bitfield<Ts...> make_bitfield(const hilti::rt::TypeInfo* ti, Ts... args) {
    return {tuple::make(std::move(args)...), ti};
}

namespace bitfield::detail {

// Helper for the HILTI codegen to render a bitfield's value into a string.
template<typename... Ts>
inline std::string render(const Bitfield<Ts...>& x, const hilti::rt::TypeInfo* type_info, bool is_anonymous) {
    if ( ! type_info )
        return "<uninitialized bitfield>";

    std::string out;

    type_info::Value bitfield(&x, type_info);
    for ( const auto& [b, v] : type_info->bitfield->iterate(bitfield) ) {
        if ( ! out.empty() )
            out += ", ";

        std::string s;
        if ( v )
            s = v.to_string();
        else
            s = "(not set)";

        if ( is_anonymous )
            out += fmt("$%s=%s", b.name, s);
        else
            out += fmt("%s: %s", b.name, s);
    }

    return out;
}

// Helper for the HILTI codegen to render an optional bitfield value into a string.
template<typename... Ts>
inline std::string render(const hilti::rt::Optional<Bitfield<Ts...>>& x, const hilti::rt::TypeInfo* type_info,
                          bool is_anonymous = false) {
    if ( ! type_info )
        return "<uninitialized bitfield>";

    if ( x.has_value() )
        return render(*x, type_info, is_anonymous);

    if ( ! is_anonymous )
        return fmt("(not set)");

    std::string out;

    Bitfield<Ts...> empty(type_info);
    type_info::Value bitfield(&empty, type_info);
    for ( const auto& [b, v] : type_info->bitfield->iterate(bitfield) ) {
        if ( ! out.empty() )
            out += ", ";

        out += fmt("$%s=(not set)", b.name);
    }

    return out;
}

} // namespace bitfield::detail


namespace detail::adl {
template<typename... Ts>
inline std::string to_string(const Bitfield<Ts...>& x, adl::tag /*unused*/) {
    return fmt("(%s)", bitfield::detail::render(x, x.ti, false));
}

template<typename... Ts>
inline std::string to_string_for_print(const Bitfield<Ts...>& x, adl::tag /*unused*/) {
    return fmt("(%s)", bitfield::detail::render(x, x.ti, false));
}
} // namespace detail::adl

} // namespace hilti::rt

namespace std {

template<typename... Ts>
inline std::ostream& operator<<(std::ostream& out, const hilti::rt::Bitfield<Ts...>& x) {
    return out << hilti::rt::to_string_for_print(x);
}

} // namespace std
