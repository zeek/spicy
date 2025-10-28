// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>

#include <hilti/rt/extension-points.h>
#include <hilti/rt/types/bytes.h>
#include <hilti/rt/types/stream.h>
#include <hilti/rt/util.h>

namespace hilti::rt {

namespace real {
/** Available formats for (un-)packing a binary floating point value. */
HILTI_RT_ENUM(Type, Undef, IEEE754_Single, IEEE754_Double);

/** Packs a floating point value into a binary representation, following the protocol for `pack` operator. */
extern Bytes pack(double d, Type type, ByteOrder fmt);

/** Unpacks a floatingpoint value from a binary representation, following the protocol for `unpack` operator. */
extern Result<Tuple<double, Bytes>> unpack(const Bytes& data, Type type, ByteOrder fmt);

/** Unpacks a floatingpoint value from a binary representation, following the protocol for `unpack` operator. */
extern Result<Tuple<double, stream::View>> unpack(const stream::View& data, Type type, ByteOrder fmt);

} // namespace real

namespace detail::adl {
std::string to_string(double x, tag /*unused*/);
std::string to_string(const real::Type& x, tag /*unused*/);
} // namespace detail::adl

} // namespace hilti::rt
