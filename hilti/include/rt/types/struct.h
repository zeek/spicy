// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

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

/**
 * Exception triggered y the ".?" operator to signal to host applications that
 * a struct attribbute isn't set.
 */
HILTI_EXCEPTION(AttributeNotSet, Exception)

namespace struct_ {

template<class T>
inline auto& value_or_exception(const std::optional<T>& t, const char* location) {
    if ( t.has_value() )
        return t.value();

    throw AttributeNotSet("struct attribute not set", location);
}
} // namespace struct_

namespace detail::adl {
template<typename T, typename std::enable_if_t<std::is_base_of<trait::isStruct, T>::value>* = nullptr>
inline std::string to_string(const T& x, adl::tag /*unused*/) {
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
