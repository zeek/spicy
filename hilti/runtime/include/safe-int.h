// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once
#include <algorithm>

#include <hilti/rt/exception.h>

#define SAFEINT_DISABLE_ADDRESS_OPERATOR

// Workaround for https://github.com/zeek/spicy/issues/1829 while is waiting to be merged.

namespace hilti::rt::debug {
// Forward-declare since `hilti/rt/logging.h` includes this header.
const char* location();
} // namespace hilti::rt::debug

#define SAFEINT_REMOVE_NOTHROW
#define SAFEINT_ASSERT(x)                                                                                              \
    throw ::hilti::rt::Overflow("overflow detected",                                                                   \
                                std::max(hilti::rt::debug::location(), static_cast<const char*>("<no location>")))

#include <hilti/rt/3rdparty/SafeInt/SafeInt.hpp>

namespace hilti::rt::integer {

namespace detail {
class SafeIntException {
public:
    static void SafeIntOnOverflow() __attribute__((noreturn)) { throw Overflow("integer overflow"); }

    static void SafeIntOnDivZero() __attribute__((noreturn)) { throw DivisionByZero("integer division by zero"); }
};
} // namespace detail

template<typename T>
using safe = SafeInt<T, detail::SafeIntException>;

} // namespace hilti::rt::integer

// Needs to be a top level.
template<typename O, typename T>
inline auto operator<<(O& out, const hilti::rt::integer::safe<T>& x)
    -> std::enable_if_t<std::is_base_of_v<std::ostream, O>, O>& {
    if ( std::is_same<T, int8_t>() )
        out << static_cast<int16_t>(x);
    else if ( std::is_same<T, uint8_t>() )
        out << static_cast<uint16_t>(x);
    else
        out << x.Ref();

    return out;
}
