// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/rt/extension-points.h>
#include <hilti/rt/types/bytes.h>
#include <hilti/rt/types/stream.h>
#include <hilti/rt/util.h>

namespace hilti::rt {

namespace real {
/** Available formats for unpacking a binary floating point value. */
enum class Type { Undef, IEEE754_Single, IEEE754_Double };

/** Unpacks a floatingpoint value from a binary represenation, following the protocol for `unpack` operator. */
extern Result<std::tuple<double, Bytes>> unpack(const Bytes& data, Type type, ByteOrder fmt);

/** Unpacks a floatingpoint value from a binary represenation, following the protocol for `unpack` operator. */
extern Result<std::tuple<double, stream::View>> unpack(const stream::View& data, Type type, ByteOrder fmt);

} // namespace real

namespace detail::adl {
inline std::string to_string(double x, adl::tag /*unused*/) {
    // %g general floating point format drops '.'
    return fmt("%g", x);
}

} // namespace detail::adl

} // namespace hilti::rt
