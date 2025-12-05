// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>

#include <hilti/rt/extension-points.h>
#include <hilti/rt/result.h>
#include <hilti/rt/types/optional.h>
#include <hilti/rt/util.h>

namespace hilti::rt {

namespace trait {
struct isStruct {};
struct hasParameters {};
} // namespace trait

namespace struct_ {

namespace tag {
/**
 * Tag for struct constructors receiving type parameters as its arguments, to
 * disambiguate them from other constructors.
 */
struct Parameters {};

/**
 * Tag for struct constructors receiving values for field initialization, to
 * disambiguate them from other constructors.
 */
struct Inits {};
} // namespace tag

template<class T>
inline auto& value_or_exception(const hilti::rt::Optional<T>& t) {
    if ( t.hasValue() )
        return t.value();

    throw AttributeNotSet("struct attribute not set");
}
} // namespace struct_

namespace detail::adl {

template<typename>
constexpr std::false_type has_hook_to_string_helper(long);

template<typename T>
// NOLINTNEXTLINE(readability/casting)
constexpr auto has_hook_to_string_helper(int)
    -> decltype(std::declval<T>().HILTI_INTERNAL(hook_to_string)(), std::true_type{});

template<typename T>
using has_hook_to_string = decltype(has_hook_to_string_helper<T>(0));

template<typename T>
inline std::string to_string(const T& x, adl::tag /*unused*/)
    requires(std::is_base_of_v<trait::isStruct, T>)
{
    if constexpr ( has_hook_to_string<T>() ) {
        if ( auto s = T(x).HILTI_INTERNAL(hook_to_string)() ) // copy because we need a non-const T
            return *s;
    }

    return x.__to_string();
}

} // namespace detail::adl

} // namespace hilti::rt
