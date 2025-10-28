// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <cinttypes>
#include <limits>
#include <string>
#include <utility>

#include <hilti/rt/extension-points.h>
#include <hilti/rt/result.h>
#include <hilti/rt/safe-int.h>
#include <hilti/rt/types/bytes.h>
#include <hilti/rt/unpack.h>
#include <hilti/rt/util.h>

namespace hilti::rt {

namespace detail::adl {
inline std::string to_string(hilti::rt::integer::safe<uint64_t> x, adl::tag /*unused*/) {
    return fmt("%" PRIu64, *x.Ptr());
}

inline std::string to_string(hilti::rt::integer::safe<int64_t> x, adl::tag /*unused*/) {
    return fmt("%" PRId64, *x.Ptr());
}

inline std::string to_string(hilti::rt::integer::safe<uint32_t> x, adl::tag /*unused*/) {
    return fmt("%" PRIu32, *x.Ptr());
}

inline std::string to_string(hilti::rt::integer::safe<int32_t> x, adl::tag /*unused*/) {
    return fmt("%" PRId32, *x.Ptr());
}

inline std::string to_string(hilti::rt::integer::safe<uint16_t> x, adl::tag /*unused*/) {
    return fmt("%" PRIu16, *x.Ptr());
}

inline std::string to_string(hilti::rt::integer::safe<int16_t> x, adl::tag /*unused*/) {
    return fmt("%" PRId16, *x.Ptr());
}

inline std::string to_string(hilti::rt::integer::safe<uint8_t> x, adl::tag /*unused*/) {
    return fmt("%" PRIu8, *x.Ptr());
}

inline std::string to_string(hilti::rt::integer::safe<int8_t> x, adl::tag /*unused*/) {
    return fmt("%" PRId8, *x.Ptr());
}

inline std::string to_string(hilti::rt::integer::safe<char> x, adl::tag /*unused*/) { return fmt("%" PRId8, *x.Ptr()); }

inline std::string to_string(uint64_t x, adl::tag /*unused*/) { return fmt("%" PRIu64, x); }

inline std::string to_string(int64_t x, adl::tag /*unused*/) { return fmt("%" PRId64, x); }

inline std::string to_string(uint32_t x, adl::tag /*unused*/) { return fmt("%" PRIu32, x); }

inline std::string to_string(int32_t x, adl::tag /*unused*/) { return fmt("%" PRId32, x); }

inline std::string to_string(uint16_t x, adl::tag /*unused*/) { return fmt("%" PRIu16, x); }

inline std::string to_string(int16_t x, adl::tag /*unused*/) { return fmt("%" PRId16, x); }

inline std::string to_string(uint8_t x, adl::tag /*unused*/) { return fmt("%" PRIu8, x); }

inline std::string to_string(int8_t x, adl::tag /*unused*/) { return fmt("%" PRId8, x); }

} // namespace detail::adl

namespace integer {
namespace detail {

template<typename T, typename D>
inline void pack(D x, uint8_t* dst, std::initializer_list<int> bytes) {
    for ( auto i : bytes ) {
        dst[sizeof(x) - i - 1] = (x & 0xff);
        x >>= 8U;
    }
}

template<typename T, typename D>
inline Result<Tuple<integer::safe<T>, D>> unpack(D b, const uint8_t* dst, std::initializer_list<int> bytes) {
    T x = 0;
    for ( auto i : bytes ) {
        x <<= 8U;
        x |= (static_cast<T>(dst[i]));
    }

    return {tuple::make(static_cast<integer::safe<T>>(x), std::move(b))};
}

} // namespace detail

template<typename T>
inline Bytes pack(integer::safe<T> i, ByteOrder fmt) {
    if ( fmt == ByteOrder::Host )
        return pack<T>(i, systemByteOrder());

    Bytes b(sizeof(T), '\0');
    auto* raw = reinterpret_cast<uint8_t*>(b.data());

    switch ( fmt.value() ) {
        case ByteOrder::Big:
        case ByteOrder::Network:
            if constexpr ( std::is_same_v<T, uint8_t> )
                raw[0] = i;
            else if constexpr ( std::is_same_v<T, int8_t> )
                raw[0] = static_cast<uint8_t>(i);
            else if constexpr ( std::is_same_v<T, uint16_t> || std::is_same_v<T, int16_t> )
                detail::pack<T>(i, raw, {0, 1});
            else if constexpr ( std::is_same_v<T, uint32_t> || std::is_same_v<T, int32_t> )
                detail::pack<T>(i, raw, {0, 1, 2, 3});
            else if constexpr ( std::is_same_v<T, uint64_t> || std::is_same_v<T, int64_t> )
                detail::pack<T>(i, raw, {0, 1, 2, 3, 4, 5, 6, 7});
            else
                abort_with_backtrace();

            break;

        case ByteOrder::Little:
            if constexpr ( std::is_same_v<T, uint8_t> )
                raw[0] = i;

            else if constexpr ( std::is_same_v<T, int8_t> )
                raw[0] = static_cast<uint8_t>(i);

            else if constexpr ( std::is_same_v<T, uint16_t> || std::is_same_v<T, int16_t> )
                detail::pack<T>(i, raw, {1, 0});

            else if constexpr ( std::is_same_v<T, uint32_t> || std::is_same_v<T, int32_t> )
                detail::pack<T>(i, raw, {3, 2, 1, 0});

            else if constexpr ( std::is_same_v<T, uint64_t> || std::is_same_v<T, int64_t> )
                detail::pack<T>(i, raw, {7, 6, 5, 4, 3, 2, 1, 0});
            else
                abort_with_backtrace();

            break;

        case ByteOrder::Host:
            // Cannot reach, we check this above.
            abort_with_backtrace();

        case ByteOrder::Undef: throw RuntimeError("attempt to pack value with undefined byte order");
    }

    return b;
}

template<typename T, typename D>
inline Result<Tuple<integer::safe<T>, D>> unpack(D b, ByteOrder fmt) {
    if ( fmt == ByteOrder::Host )
        return unpack<T>(std::move(b), systemByteOrder());

    if ( b.size() < static_cast<int64_t>(sizeof(T)) )
        return result::Error("insufficient data to unpack integer");

    uint8_t raw[sizeof(T)];
    b = b.extract(raw, sizeof(raw));

    switch ( fmt.value() ) {
        case ByteOrder::Big:
        case ByteOrder::Network:
            if constexpr ( std::is_same_v<T, uint8_t> )
                return {tuple::make(static_cast<integer::safe<uint8_t>>(raw[0]), std::move(b))};

            if constexpr ( std::is_same_v<T, int8_t> ) {
                auto x = static_cast<int8_t>(raw[0]); // Forced cast to skip safe<T> range check.
                return {tuple::make(static_cast<integer::safe<int8_t>>(x), std::move(b))};
            }

            if constexpr ( std::is_same_v<T, uint16_t> || std::is_same_v<T, int16_t> )
                return detail::unpack<T>(std::move(b), raw, {0, 1});

            if constexpr ( std::is_same_v<T, uint32_t> || std::is_same_v<T, int32_t> )
                return detail::unpack<T>(std::move(b), raw, {0, 1, 2, 3});

            if constexpr ( std::is_same_v<T, uint64_t> || std::is_same_v<T, int64_t> )
                return detail::unpack<T>(std::move(b), raw, {0, 1, 2, 3, 4, 5, 6, 7});

            abort_with_backtrace();

        case ByteOrder::Little:
            if constexpr ( std::is_same_v<T, uint8_t> )
                return {tuple::make(static_cast<integer::safe<uint8_t>>(raw[0]), std::move(b))};

            if constexpr ( std::is_same_v<T, int8_t> ) {
                auto x = static_cast<int8_t>(raw[0]); // Forced cast to skip safe<T> range check.
                return {tuple::make(static_cast<integer::safe<int8_t>>(x), std::move(b))};
            }

            if constexpr ( std::is_same_v<T, uint16_t> || std::is_same_v<T, int16_t> )
                return detail::unpack<T>(std::move(b), raw, {1, 0});

            if constexpr ( std::is_same_v<T, uint32_t> || std::is_same_v<T, int32_t> )
                return detail::unpack<T>(std::move(b), raw, {3, 2, 1, 0});

            if constexpr ( std::is_same_v<T, uint64_t> || std::is_same_v<T, int64_t> )
                return detail::unpack<T>(std::move(b), raw, {7, 6, 5, 4, 3, 2, 1, 0});

            abort_with_backtrace();

        case ByteOrder::Host:
            // Cannot reach, we check this above.
            abort_with_backtrace();

        case ByteOrder::Undef: return result::Error("undefined byte order");
    }

    cannot_be_reached();
}

/**
 * Converts a 64-bit value from host-order to network order.
 *
 * v: The value to convert.
 */
extern uint64_t hton64(uint64_t v);

/**
 * Converts a 32-bit value from host-order to network order.
 *
 * v: The value to convert.
 */
extern uint32_t hton32(uint32_t v);

/**
 * Converts a 16-bit value from host-order to network order.
 *
 * v: The value to convert.
 */
extern uint16_t hton16(uint16_t v);

/**
 * Converts a 64-bit value from host-order to network order.
 *
 * v: The value to convert.
 */
extern uint64_t ntoh64(uint64_t v);

/**
 * Converts a 32-bit value from host-order to network order.
 *
 * v: The value to convert.
 */
extern uint32_t ntoh32(uint32_t v);

/**
 * Converts a 16-bit value from host-order to network order.
 *
 * v: The value to convert.
 */
extern uint16_t ntoh16(uint16_t v);

/**
 * Reverses the bytes of a 16-bit value.
 *
 * v: The value to convert.
 */
extern uint16_t flip16(uint16_t v);

/**
 * Reverses the bytes of a 32-bit value.
 *
 * v: The value to convert.
 */
extern uint32_t flip32(uint32_t v);

/**
 * Reverses the bytes of a 64-bit value.
 *
 * v: The value to convert.
 */
extern uint64_t flip64(uint64_t v);

/**
 * Flips a signed integer's byte order.
 *
 * @param v integer to flip
 * @param n number of valid bytes in *v*
 * @return value with *n* bits of *v* flipped in their byte order
 */
inline int64_t flip(int64_t v, uint64_t n) {
    if ( n == 0 )
        return v;
    auto i = static_cast<uint64_t>(v);
    i = flip64(i) >> (64 - n * 8);
    return static_cast<int64_t>(i);
}

/**
 * Flips an unsigned integer's byte order.
 *
 * @param v unsigned integer to flip
 * @param n number of valid bytes in *v*
 * @return value with *n* bits of *v* flipped in their byte order
 */
inline uint64_t flip(uint64_t v, uint64_t n) {
    if ( n == 0 )
        return v;
    return (flip64(v) >> (64 - n * 8));
}

/** Available bit orders. */
HILTI_RT_ENUM(BitOrder, LSB0, MSB0, Undef);

/** Extracts a range of bits from an integer value, shifting them to the very left before returning. */
template<typename UINT>
inline hilti::rt::integer::safe<UINT> bits(hilti::rt::integer::safe<UINT> v, uint64_t lower, uint64_t upper,
                                           BitOrder bo) {
    constexpr auto width = std::numeric_limits<UINT>::digits;

    if ( lower > upper )
        throw InvalidArgument("lower limit needs to be less or equal the upper limit");

    if ( upper >= width )
        throw InvalidArgument("upper limit needs to be less or equal the input width");

    switch ( bo.value() ) {
        case BitOrder::LSB0: break;

        case BitOrder::MSB0:
            lower = (width - lower - 1);
            upper = (width - upper - 1);
            std::swap(lower, upper);
            break;

        case BitOrder::Undef: throw RuntimeError("undefined bit order");
    }

    assert(lower <= upper);
    const auto range = upper - lower + 1;

    // If the range to extract equals the width there is no work to do.
    //
    // NOTE: Not returning early here would lead to a shift beyond the width below.
    if ( range == width )
        return v;

    const auto mask = ((static_cast<uint64_t>(1) << range) - static_cast<uint64_t>(1U)) << lower;
    return (v & mask) >> lower;
}

/**
 * Helper function just returning the value passed in. This is for working
 * around an issue where our code generator produces code that, for unknown
 * reasons, doesn't compile if the value is used directly.
 */
template<typename UINT>
inline hilti::rt::integer::safe<UINT> noop(hilti::rt::integer::safe<UINT> v) {
    return v;
}

} // namespace integer

namespace detail::adl {
std::string to_string(const integer::BitOrder& x, tag /*unused*/);
}

} // namespace hilti::rt
