// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#define SAFEINT_DISABLE_ADDRESS_OPERATOR
#include <hilti/rt/3rdparty/SafeInt/SafeInt.hpp>
#include <hilti/rt/exception.h>

namespace hilti::rt::integer {

namespace detail {
class SafeIntException {
public:
    // SafeInt API methods.
    static void SafeIntOnOverflow() __attribute__((noreturn)) { throw Overflow("integer overflow"); }
    static void SafeIntOnDivZero() __attribute__((noreturn)) { throw DivisionByZero("integer division by zero"); }
};
} // namespace detail

template<typename T>
using safe = SafeInt<T, detail::SafeIntException>;

} // namespace hilti::rt::integer

// Needs to be a top level.
template<typename O, typename T>
inline auto operator<<(O& out, const hilti::rt::integer::safe<T>& x) -> O&
    requires(std::is_base_of_v<std::ostream, O>)
{
    if ( std::is_same<T, int8_t>() )
        out << static_cast<int16_t>(x);
    else if ( std::is_same<T, uint8_t>() )
        out << static_cast<uint16_t>(x);
    else
        out << x.Ref();

    return out;
}
