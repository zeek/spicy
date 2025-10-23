// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <tuple>

#include <hilti/rt/result.h>
#include <hilti/rt/types/bytes.h>
#include <hilti/rt/types/integer.h>
#include <hilti/rt/types/real.h>
#include <hilti/rt/types/stream.h>
#include <hilti/rt/types/tuple.h>

using namespace hilti::rt;
using namespace hilti::rt::bytes::literals;

namespace std {
template<typename T>
ostream& operator<<(ostream& stream, const Result<T>& x) {
    if ( x.hasValue() )
        return stream << fmt("Ok(%s)", x.value());
    else
        return stream << fmt("Error(%s)", x.error());
}
} // namespace std

TEST_SUITE_BEGIN("real");

TEST_CASE("pack") {
    SUBCASE("IEEE754_Single") {
        CHECK_EQ(real::pack(0.5, real::Type::IEEE754_Single, ByteOrder::Big), "\x3f\x00\x00\x00"_b);
        CHECK_EQ(real::pack(0.75, real::Type::IEEE754_Single, ByteOrder::Big), "\x3f\x40\x00\x00"_b);
        CHECK_EQ(real::pack(0.5, real::Type::IEEE754_Single, ByteOrder::Little), "\x00\x00\x00\x3f"_b);
        CHECK_EQ(real::pack(0.75, real::Type::IEEE754_Single, ByteOrder::Little), "\x00\x00\x40\x3f"_b);
        CHECK_THROWS_WITH_AS(real::pack(1.0, real::Type::Undef, ByteOrder::Big),
                             "attempt to pack real value of undefined type", const RuntimeError&);
        CHECK_THROWS_WITH_AS(real::pack(1.0, real::Type::IEEE754_Single, ByteOrder::Undef),
                             "attempt to pack value with undefined byte order", const RuntimeError&);
    }

    SUBCASE("IEEE754_Double") {
        CHECK_EQ(real::pack(0.5, real::Type::IEEE754_Double, ByteOrder::Big), "\x3f\xe0\x00\x00\x00\x00\x00\x00"_b);
        CHECK_EQ(real::pack(0.75, real::Type::IEEE754_Double, ByteOrder::Big), "\x3f\xe8\x00\x00\x00\x00\x00\x00"_b);
        CHECK_EQ(real::pack(0.5, real::Type::IEEE754_Double, ByteOrder::Little), "\x00\x00\x00\x00\x00\x00\xe0\x3f"_b);
        CHECK_EQ(real::pack(0.75, real::Type::IEEE754_Double, ByteOrder::Little), "\x00\x00\x00\x00\x00\x00\xe8\x3f"_b);
    }
}

TEST_CASE("unpack") {
    SUBCASE("Bytes") {
        using Result = Result<Tuple<double, Bytes>>;

        SUBCASE("IEEE754_Single") {
            CHECK_EQ(real::unpack("\x3f\x00\x00"_b, real::Type::IEEE754_Single, ByteOrder::Big),
                     Result(result::Error("insufficient data to unpack single precision real")));

            CHECK_EQ(real::unpack("\x3f\x00\x00\x00"_b, real::Type::IEEE754_Single, ByteOrder::Big),
                     Result(std::make_tuple(0.5, ""_b)));
            CHECK_EQ(real::unpack("\x3f\x40\x00\x00\x01\x02\x03\x04"_b, real::Type::IEEE754_Single, ByteOrder::Big),
                     Result(std::make_tuple(0.75, "\x01\x02\x03\x04"_b)));

            CHECK_EQ(real::unpack("\x00\x00\x00\x3f"_b, real::Type::IEEE754_Single, ByteOrder::Little),
                     Result(std::make_tuple(0.5, ""_b)));
            CHECK_EQ(real::unpack("\x00\x00\x40\x3f\x01\x02\x03\x04"_b, real::Type::IEEE754_Single, ByteOrder::Little),
                     Result(std::make_tuple(0.75, "\x01\x02\x03\x04"_b)));

            CHECK_EQ(real::unpack("\x00\x00\x00\x3f"_b, real::Type::IEEE754_Single, ByteOrder::Big),
                     real::unpack("\x00\x00\x00\x3f"_b, real::Type::IEEE754_Single, ByteOrder::Network));
        }

        SUBCASE("IEEE754_Double") {
            CHECK_EQ(real::unpack("\x3f\x00\x00\x00\x00\x00\x00"_b, real::Type::IEEE754_Double, ByteOrder::Big),
                     Result(result::Error("insufficient data to unpack double precision real")));

            CHECK_EQ(real::unpack("\x3f\xe0\x00\x00\x00\x00\x00\x00"_b, real::Type::IEEE754_Double, ByteOrder::Big),
                     Result(std::make_tuple(0.5, ""_b)));
            CHECK_EQ(real::unpack("\x3f\xe8\x00\x00\x00\x00\x00\x00\x01\x02\x03\x04"_b, real::Type::IEEE754_Double,
                                  ByteOrder::Big),
                     Result(std::make_tuple(0.75, "\x01\x02\x03\x04"_b)));

            CHECK_EQ(real::unpack("\x00\x00\x00\x00\x00\x00\xe0\x3f"_b, real::Type::IEEE754_Double, ByteOrder::Little),
                     Result(std::make_tuple(0.5, ""_b)));
            CHECK_EQ(real::unpack("\x00\x00\x00\x00\x00\x00\xe8\x3f\x01\x02\x03\x04"_b, real::Type::IEEE754_Double,
                                  ByteOrder::Little),
                     Result(std::make_tuple(0.75, "\x01\x02\x03\x04"_b)));

            CHECK_EQ(real::unpack("\x00\x00\x00\x00\x00\x00\x00\x3f"_b, real::Type::IEEE754_Double, ByteOrder::Big),
                     real::unpack("\x00\x00\x00\x00\x00\x00\x00\x3f"_b, real::Type::IEEE754_Double,
                                  ByteOrder::Network));
        }

        SUBCASE("undef types") {
            const auto xs = "\x00\x00\x00\x00\x00\x00\x00\x00"_b;

            CHECK_EQ(real::unpack(xs, real::Type::Undef, ByteOrder::Little),
                     Result(result::Error("undefined real type for unpacking")));
            CHECK_EQ(real::unpack(xs, real::Type::IEEE754_Single, ByteOrder::Undef),
                     Result(result::Error("undefined byte order")));
            CHECK_EQ(real::unpack(xs, real::Type::IEEE754_Double, ByteOrder::Undef),
                     Result(result::Error("undefined byte order")));
        }
    }

    SUBCASE("Stream") {
        // We only test stream-related properties here as the handling
        // of `Byte` and `Stream` shares most of their code.

        // This test is value-parameterized over `expanding`.
        bool expanding = true;
        SUBCASE("expanding") { expanding = true; }
        SUBCASE("not expanding") { expanding = false; }

        using Result = Result<Tuple<double, stream::View>>;

        const auto s1 = Stream("\x3f\x40\x00\x00\x01\x02\x03\x04"_b);
        const auto s2 = Stream(R"(?@)");

        const auto r1 = real::unpack(s1.view(expanding), real::Type::IEEE754_Single, ByteOrder::Big);
        CHECK_EQ(r1, Result(std::make_tuple(0.75, Stream("\x01\x02\x03\x04").view(! expanding))));

        REQUIRE(r1);
        CHECK_EQ(tuple::get<1>(*r1).isOpenEnded(), expanding);

        CHECK_EQ(real::unpack(s2.view(expanding), real::Type::IEEE754_Single, ByteOrder::Big),
                 Result(result::Error("insufficient data to unpack single precision real")));
    }
}

TEST_SUITE_END();
