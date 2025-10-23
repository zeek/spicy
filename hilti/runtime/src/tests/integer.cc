// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <bitset>
#include <cmath>
#include <limits>

#include <hilti/rt/result.h>
#include <hilti/rt/safe-int.h>
#include <hilti/rt/types/bytes.h>
#include <hilti/rt/types/integer.h>
#include <hilti/rt/types/string.h>
#include <hilti/rt/types/tuple.h>

using namespace hilti::rt;
using namespace hilti::rt::bytes::literals;

template<typename T>
std::ostream& operator<<(std::ostream& stream, const Result<T>& x) {
    if ( x.hasValue() )
        return stream << "Ok(" << *x << ')';
    else
        return stream << fmt("Error(%s)", x.error());
}

TEST_SUITE_BEGIN("Integer");

TEST_CASE("flip16") {
    CHECK_EQ(integer::flip16(0), 256 * 0);
    CHECK_EQ(integer::flip16(1), 256 * 1);
    CHECK_EQ(integer::flip16(2), 256 * 2);
    CHECK_EQ(integer::flip16(3), 256 * 3);

    const auto max = std::numeric_limits<uint16_t>::max();

    // NOLINTNEXTLINE(bugprone-integer-division)
    CHECK_EQ(integer::flip16(max / 2), std::pow(256, 2) - 256 / 2 - 1);

    CHECK_EQ(integer::flip16(max - 3), std::pow(256, 2) - 256 * 3 - 1);
    CHECK_EQ(integer::flip16(max - 2), std::pow(256, 2) - 256 * 2 - 1);
    CHECK_EQ(integer::flip16(max - 1), std::pow(256, 2) - 256 * 1 - 1);
    CHECK_EQ(integer::flip16(max - 0), std::pow(256, 2) - 256 * 0 - 1);
}

TEST_CASE("flip32") {
    CHECK_EQ(integer::flip32(0), 0);
    CHECK_EQ(integer::flip32(1), std::pow(256, 3) * 1);
    CHECK_EQ(integer::flip32(2), std::pow(256, 3) * 2);
    CHECK_EQ(integer::flip32(3), std::pow(256, 3) * 3);

    const auto max = std::numeric_limits<uint32_t>::max();

    // NOLINTNEXTLINE(bugprone-integer-division)
    CHECK_EQ(integer::flip32(max / 2), std::pow(static_cast<uint64_t>(256), 4) - 256 / 2 - 1);

    CHECK_EQ(integer::flip32(max - 3), std::pow(static_cast<uint64_t>(256), 4) - std::pow(256, 3) * 3 - 1);
    CHECK_EQ(integer::flip32(max - 2), std::pow(static_cast<uint64_t>(256), 4) - std::pow(256, 3) * 2 - 1);
    CHECK_EQ(integer::flip32(max - 1), std::pow(static_cast<uint64_t>(256), 4) - std::pow(256, 3) * 1 - 1);
    CHECK_EQ(integer::flip32(max - 0), std::pow(static_cast<uint64_t>(256), 4) - std::pow(256, 3) * 0 - 1);
}

TEST_CASE("flip64") {
    CHECK_EQ(integer::flip64(0), 0);
    CHECK_EQ(integer::flip64(1), std::pow(static_cast<uint64_t>(256), 7) * 1);
    CHECK_EQ(integer::flip64(2), std::pow(256, 7) * 2);
    CHECK_EQ(integer::flip64(3), std::pow(256, 7) * 3);

    const auto max = std::numeric_limits<uint32_t>::max();

    CHECK_EQ(integer::flip64(max / 2), 18446743519658770432ULL);

    CHECK_EQ(integer::flip64(max - 3), 18230571287300800512ULL);
    CHECK_EQ(integer::flip64(max - 2), 18302628881338728448ULL);
    CHECK_EQ(integer::flip64(max - 1), 18374686475376656384ULL);
    CHECK_EQ(integer::flip64(max - 0), 18446744069414584320ULL);
}

TEST_CASE("flip") {
    constexpr size_t BITS = 64;
    constexpr size_t BYTES = BITS / 8;

    SUBCASE("uint64_t") {
        {
            const auto b1 = std::bitset<BITS>("1100000000000000000000000000000010111111111111111111111111111111");
            const auto b2 = std::bitset<BITS>("1111111111111111111111111011111100000000000000000000000011000000");
            CHECK_EQ(integer::flip(static_cast<uint64_t>(b1.to_ullong()), BYTES), b2.to_ullong());
        }

        {
            const auto b1 = std::bitset<BITS>("1100000000000000000000000000000010111111111111111111111111111111");
            const auto b2 = std::bitset<BITS>("0000000000000000000000000000000011111111111111111111111110111111");
            CHECK_EQ(integer::flip(static_cast<uint64_t>(b1.to_ullong()), BYTES / 2), b2.to_ullong());
        }

        {
            const auto b1 = std::bitset<BITS>("1100000000000000000000000000000010111111111111111111111111111111");
            const auto b2 = std::bitset<BITS>("0000000000000000000000000000000000000000000000001111111111111111");
            CHECK_EQ(integer::flip(static_cast<uint64_t>(b1.to_ullong()), BYTES / 4), b2.to_ullong());
        }

        {
            const auto b1 = std::bitset<BITS>("1100000000000000000000000000000010111111111111111111111111111111");
            const auto b2 = std::bitset<BITS>("0000000000000000000000000000000000000000000000000000000011111111");
            CHECK_EQ(integer::flip(static_cast<uint64_t>(b1.to_ullong()), BYTES / 8), b2.to_ullong());
        }

        {
            const auto b1 = std::bitset<BITS>("1100000000000000000000000000000010111111111111111111111111111111");
            CHECK_EQ(integer::flip(static_cast<uint64_t>(b1.to_ullong()), 0), b1.to_ullong());
        }
    }

    SUBCASE("int64_t") {
        {
            const auto b1 = std::bitset<BITS>("1100000000000000000000000000000010111111111111111111111111111111");
            const auto b2 = std::bitset<BITS>("1111111111111111111111111011111100000000000000000000000011000000");
            CHECK_EQ(integer::flip(static_cast<int64_t>(b1.to_ullong()), BYTES), static_cast<int64_t>(b2.to_ullong()));
        }

        {
            const auto b1 = std::bitset<BITS>("1100000000000000000000000000000010111111111111111111111111111111");
            const auto b2 = std::bitset<BITS>("0000000000000000000000000000000011111111111111111111111110111111");
            CHECK_EQ(integer::flip(static_cast<int64_t>(b1.to_ullong()), BYTES / 2),
                     static_cast<int64_t>(b2.to_ullong()));
        }

        {
            const auto b1 = std::bitset<BITS>("1100000000000000000000000000000010111111111111111111111111111111");
            const auto b2 = std::bitset<BITS>("0000000000000000000000000000000000000000000000001111111111111111");
            CHECK_EQ(integer::flip(static_cast<int64_t>(b1.to_ullong()), BYTES / 4),
                     static_cast<int64_t>(b2.to_ullong()));
        }

        {
            const auto b1 = std::bitset<BITS>("1100000000000000000000000000000010111111111111111111111111111111");
            const auto b2 = std::bitset<BITS>("0000000000000000000000000000000000000000000000000000000011111111");
            CHECK_EQ(integer::flip(static_cast<int64_t>(b1.to_ullong()), BYTES / 8),
                     static_cast<int64_t>(b2.to_ullong()));
        }

        {
            const auto b1 = std::bitset<BITS>("1100000000000000000000000000000010111111111111111111111111111111");
            CHECK_EQ(integer::flip(static_cast<int64_t>(b1.to_ullong()), 0), static_cast<int64_t>(b1.to_ullong()));
        }
    }
}

TEST_CASE("bits") {
    auto uint8 = [](const char* b) -> integer::safe<uint8_t> { return std::bitset<8>(b).to_ulong(); };

    CHECK_EQ(integer::bits(uint8("00001111"), 0, 0, integer::BitOrder::MSB0), uint8("0"));
    CHECK_EQ(integer::bits(uint8("00001111"), 0, 1, integer::BitOrder::MSB0), uint8("00"));
    CHECK_EQ(integer::bits(uint8("00001111"), 0, 2, integer::BitOrder::MSB0), uint8("000"));
    CHECK_EQ(integer::bits(uint8("00001111"), 0, 3, integer::BitOrder::MSB0), uint8("0000"));
    CHECK_EQ(integer::bits(uint8("00001111"), 0, 4, integer::BitOrder::MSB0), uint8("00001"));
    CHECK_EQ(integer::bits(uint8("00001111"), 0, 5, integer::BitOrder::MSB0), uint8("000011"));

    CHECK_EQ(integer::bits(uint8("00001111"), 0, 0, integer::BitOrder::LSB0), uint8("1"));
    CHECK_EQ(integer::bits(uint8("00001111"), 0, 1, integer::BitOrder::LSB0), uint8("11"));
    CHECK_EQ(integer::bits(uint8("00001111"), 0, 2, integer::BitOrder::LSB0), uint8("111"));
    CHECK_EQ(integer::bits(uint8("00001111"), 0, 3, integer::BitOrder::LSB0), uint8("1111"));
    CHECK_EQ(integer::bits(uint8("00001111"), 0, 4, integer::BitOrder::LSB0), uint8("01111"));
    CHECK_EQ(integer::bits(uint8("00001111"), 0, 5, integer::BitOrder::LSB0), uint8("001111"));

    CHECK_THROWS_WITH_AS(integer::bits(integer::safe<uint8_t>(0), 3, 0, integer::BitOrder::MSB0),
                         "lower limit needs to be less or equal the upper limit", const InvalidArgument&);
    CHECK_THROWS_WITH_AS(integer::bits(integer::safe<uint8_t>(0), 1, 8, integer::BitOrder::MSB0),
                         "upper limit needs to be less or equal the input width", const InvalidArgument&);
    CHECK_THROWS_WITH_AS(integer::bits(integer::safe<uint8_t>(0), 0, 3, integer::BitOrder::Undef),
                         "undefined bit order", const RuntimeError&);

    // Extracting all bits should reproduce the input.
    CHECK_EQ(hilti::rt::integer::bits(hilti::rt::integer::safe<uint64_t>(72623859790382848),
                                      hilti::rt::integer::safe<std::uint64_t>{0U},
                                      hilti::rt::integer::safe<std::uint64_t>{63U}, hilti::rt::integer::BitOrder::LSB0),
             72623859790382848);
}

TEST_CASE("pack") {
    CHECK_EQ(integer::pack<uint16_t>(1, ByteOrder::Little), "\x01\x00"_b);
    CHECK_EQ(integer::pack<uint16_t>(256, ByteOrder::Big), "\x01\x00"_b);
    CHECK_EQ(integer::pack<uint16_t>(256, ByteOrder::Little), "\x00\x01"_b);
    CHECK_EQ(integer::pack<uint16_t>(1, ByteOrder::Big), "\x00\x01"_b);
    CHECK_THROWS_WITH_AS(integer::pack<uint16_t>(1, ByteOrder::Undef),
                         "attempt to pack value with undefined byte order", const RuntimeError&);

    CHECK_EQ(integer::pack<uint32_t>(0x01020304, ByteOrder::Big), "\x01\x02\x03\x04"_b);
    CHECK_EQ(integer::pack<uint32_t>(0x01020304, ByteOrder::Little), "\x04\x03\x02\x01"_b);
    CHECK_EQ(integer::pack<uint64_t>(0x0102030405060708, ByteOrder::Big), "\x01\x02\x03\x04\x05\x06\x07\x08"_b);
    CHECK_EQ(integer::pack<uint64_t>(0x0102030405060708, ByteOrder::Little), "\x08\x07\x06\x05\x04\x03\x02\x01"_b);
}

TEST_CASE("unpack") {
    using Result16 = Result<Tuple<integer::safe<uint16_t>, Bytes>>;
    using Result32 = Result<Tuple<integer::safe<uint32_t>, Bytes>>;
    using Result64 = Result<Tuple<integer::safe<uint64_t>, Bytes>>;

    CHECK_EQ(integer::unpack<uint16_t>(""_b, ByteOrder::Little),
             Result16(result::Error("insufficient data to unpack integer")));
    CHECK_EQ(integer::unpack<uint16_t>("\x01"_b, ByteOrder::Little),
             Result16(result::Error("insufficient data to unpack integer")));
    CHECK_EQ(integer::unpack<uint16_t>("\x00\x01"_b, ByteOrder::Undef),
             Result16(result::Error("undefined byte order")));

    CHECK_EQ(integer::unpack<uint16_t>("\x01\x00"_b, ByteOrder::Little), Result16(std::make_tuple(1, ""_b)));
    CHECK_EQ(integer::unpack<uint16_t>("\x01\x00"_b, ByteOrder::Big), Result16(std::make_tuple(256, ""_b)));
    CHECK_EQ(integer::unpack<uint16_t>("\x00\x01"_b, ByteOrder::Little), Result16(std::make_tuple(256, ""_b)));
    CHECK_EQ(integer::unpack<uint16_t>("\x00\x01"_b, ByteOrder::Big), Result16(std::make_tuple(1, ""_b)));

    CHECK_EQ(integer::unpack<uint32_t>("\x01\x02\x03\x04"_b, ByteOrder::Big),
             Result32(std::make_tuple(0x01020304, ""_b)));
    CHECK_EQ(integer::unpack<uint32_t>("\x04\x03\x02\x01"_b, ByteOrder::Little),
             Result32(std::make_tuple(0x01020304, ""_b)));
    CHECK_EQ(integer::unpack<uint64_t>("\x01\x02\x03\x04\x05\x06\x07\x08"_b, ByteOrder::Big),
             Result64(std::make_tuple(0x0102030405060708, ""_b)));
    CHECK_EQ(integer::unpack<uint64_t>("\x08\x07\x06\x05\x04\x03\x02\x01"_b, ByteOrder::Little),
             Result64(std::make_tuple(0x0102030405060708, ""_b)));
}

TEST_SUITE_END();
