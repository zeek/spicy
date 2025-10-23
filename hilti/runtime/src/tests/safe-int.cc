// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <limits>

#include <hilti/rt/safe-int.h>

using namespace hilti::rt;

TEST_SUITE_BEGIN("safe-int");

TEST_CASE("construct") {
    CHECK_EQ(integer::safe<int64_t>(), 0);
    CHECK_EQ(integer::safe<int64_t>(-1), -1);
    CHECK_THROWS_WITH_AS(integer::safe<uint64_t>(-1), "integer overflow", const Overflow&);
    CHECK_THROWS_WITH_AS(integer::safe<int8_t>(1024), "integer overflow", const Overflow&);
}

TEST_CASE("operations") {
    const auto zero = integer::safe<int8_t>(0);
    const auto one = integer::safe<int8_t>(1);
    const auto max = integer::safe<int8_t>(std::numeric_limits<int8_t>::max());

    CHECK_EQ(zero + zero, zero);
    CHECK_EQ(one + zero, one);
    CHECK_EQ(max + zero, max);
    CHECK_THROWS_WITH_AS(max + one, "integer overflow", const Overflow&);

    CHECK_EQ(zero - zero, zero);
    CHECK_EQ(one - zero, one);
    CHECK_EQ(max - zero, max);
    CHECK_EQ(max - max, zero);
    CHECK_THROWS_WITH_AS(zero - max - max, "integer overflow", const Overflow&);

    CHECK_EQ(zero * zero, zero);
    CHECK_EQ(one * zero, zero);
    CHECK_EQ(one * one, one);
    CHECK_EQ(max * one, max);
    CHECK_THROWS_WITH_AS(max * max, "integer overflow", const Overflow&);

    CHECK_THROWS_WITH_AS(zero / zero, "integer division by zero", const DivisionByZero&);
    CHECK_EQ(zero / one, zero);
    CHECK_EQ(one / one, one);
    CHECK_THROWS_WITH_AS(max / zero, "integer division by zero", const DivisionByZero&);
    CHECK_EQ(max / one, max);
    CHECK_EQ(max / max, one);
    CHECK_EQ(one / max, zero);
}

TEST_CASE("fmt") {
    CHECK_EQ(fmt("%d", integer::safe<uint8_t>(42)), "42");
    CHECK_EQ(fmt("%d", integer::safe<int8_t>(42)), "42");
    CHECK_EQ(fmt("%d", integer::safe<int16_t>(42)), "42");
    CHECK_EQ(fmt("%d", integer::safe<int32_t>(42)), "42");
    CHECK_EQ(fmt("%d", integer::safe<int64_t>(42)), "42");
}

TEST_SUITE_END();
