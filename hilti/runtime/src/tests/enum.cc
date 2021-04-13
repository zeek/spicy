// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#include <hilti/rt/doctest.h>
#include <hilti/rt/exception.h>
#include <hilti/rt/types/enum.h>

using namespace hilti::rt;

TEST_SUITE_BEGIN("Enum");

enum class X : int64_t { A1 = 1, A2 = 2, A3 = -2, Undef = -1 };

TEST_CASE("from_int") {
    CHECK_EQ(enum_::from_int<X>(1), X::A1);
    CHECK_EQ(enum_::from_int<X>(1ll), X::A1);
    CHECK_EQ(enum_::from_int<X>(-2), X::A3);
    CHECK_EQ(enum_::from_int<X>(10), static_cast<X>(10));
}

TEST_CASE("from_uint") {
    CHECK_EQ(enum_::from_uint<X>(1), X::A1);
    CHECK_EQ(enum_::from_uint<X>(1ull), X::A1);
    CHECK_EQ(enum_::from_uint<X>(10), static_cast<X>(10));

    CHECK_THROWS_AS(enum_::from_uint<X>(std::numeric_limits<uint64_t>::max()), InvalidValue);
}

TEST_SUITE_END();
