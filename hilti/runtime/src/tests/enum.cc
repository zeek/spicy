// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#include <hilti/rt/doctest.h>
#include <hilti/rt/exception.h>
#include <hilti/rt/types/enum.h>

using namespace hilti::rt;

TEST_SUITE_BEGIN("Enum");

struct X {
    enum Value : int64_t { A1 = 1, A2 = 2, A3 = -2, Undef = -1 };
    constexpr X(int64_t _value = Undef) : value(_value) {}
    friend constexpr bool operator==(const X& a, const X& b) { return a.value == b.value; }
    friend constexpr bool operator!=(const X& a, const X& b) { return ! (a == b); }
    friend constexpr bool operator<(const X& a, const X& b) { return a.value < b.value; }
    int64_t value;
};

TEST_CASE("from_int") {
    CHECK_EQ(enum_::from_int<X>(1), X::A1);
    CHECK_EQ(enum_::from_int<X>(1LL), X::A1);
    CHECK_EQ(enum_::from_int<X>(-2), X::A3);
    CHECK_EQ(enum_::from_int<X>(10), static_cast<X>(10));
}

TEST_CASE("from_uint") {
    CHECK_EQ(enum_::from_uint<X>(1), X::A1);
    CHECK_EQ(enum_::from_uint<X>(1ULL), X::A1);
    CHECK_EQ(enum_::from_uint<X>(10), static_cast<X>(10));

    CHECK_THROWS_AS(enum_::from_uint<X>(std::numeric_limits<uint64_t>::max()), InvalidValue);
}

TEST_SUITE_END();
