// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>

#include <hilti/rt/extension-points.h>
#include <hilti/rt/result.h>
#include <hilti/rt/util.h>

namespace hilti::rt {

namespace trait {
struct isStruct {};
struct hasParameters {};
} // namespace trait

namespace struct_ {

template<class T>
inline auto& value_or_exception(const std::optional<T>& t) {
    if ( t.has_value() )
        return t.value();

    throw AttributeNotSet("struct attribute not set");
}
} // namespace struct_

namespace detail::adl {

template<typename>
constexpr std::false_type has__str__helper(long);

template<typename T>
constexpr auto has__str__helper(int) -> decltype(std::declval<T>().__str__(), std::true_type{});

template<typename T>
using has__str__ = decltype(has__str__helper<T>(0));

template<typename T, typename std::enable_if_t<std::is_base_of<trait::isStruct, T>::value>* = nullptr>
inline std::string to_string(const T& x, adl::tag /*unused*/) {
    if constexpr ( has__str__<T>() ) {
        if ( auto s = T(x).__str__() ) // copy because we need a non-const T
            return *s;
    }

    std::string fields;
    bool first = true;

    auto render_one = [&](auto k, auto v) {
        if ( ! first )
            fields += ", ";
        else
            first = false;

        fields += fmt("$%s=%s", k, hilti::rt::to_string(v));
    };

    x.__visit(render_one);
    return fmt("[%s]", fields);
}

} // namespace detail::adl

} // namespace hilti::rt
