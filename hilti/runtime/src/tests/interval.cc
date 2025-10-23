// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <hilti/rt/types/integer.h>
#include <hilti/rt/types/interval.h>

using namespace hilti::rt;

TEST_SUITE_BEGIN("Interval");

TEST_CASE("construct") {
    CHECK_EQ(Interval(integer::safe<uint64_t>(1), Interval::SecondTag()).seconds(), 1);
    CHECK_EQ(Interval(integer::safe<uint64_t>(1'000'000'000), Interval::NanosecondTag()).seconds(), 1);
    CHECK_EQ(Interval(integer::safe<int64_t>(-1), Interval::SecondTag()).seconds(), -1);
    CHECK_EQ(Interval(integer::safe<int64_t>(-1'000'000'000), Interval::NanosecondTag()).seconds(), -1);
    CHECK_EQ(Interval(2.5, Interval::SecondTag()).seconds(), 2.5);
    CHECK_EQ(Interval(1e-9, Interval::SecondTag()), Interval(integer::safe<uint64_t>(1), Interval::NanosecondTag()));
    CHECK_EQ(Interval(0, Interval::SecondTag()), Interval());
}

TEST_CASE("seconds") {
    CHECK_EQ(Interval(2.5, Interval::SecondTag()).seconds(), 2.5);
    CHECK_EQ(Interval(0, Interval::SecondTag()).seconds(), 0);
    CHECK_EQ(Interval(-2.5, Interval::SecondTag()).seconds(), -2.5);

    CHECK_THROWS_WITH_AS(Interval(-1e42, Interval::SecondTag{}).seconds(), "value cannot be represented as an interval",
                         const RuntimeError&);
    CHECK_THROWS_WITH_AS(Interval(1e42, Interval::SecondTag{}).seconds(), "value cannot be represented as an interval",
                         const RuntimeError&);
}

TEST_CASE("nanoseconds") {
    CHECK_EQ(Interval(1e-9, Interval::SecondTag()).nanoseconds(), 1);
    CHECK_EQ(Interval(0, Interval::SecondTag()).nanoseconds(), 0);
    CHECK_EQ(Interval(-1e-9, Interval::SecondTag()).nanoseconds(), -1);
}

TEST_CASE("comparison") {
    const auto negative_small = Interval(integer::safe<int64_t>(-123), Interval::NanosecondTag());
    const auto zero = Interval();
    const auto small = Interval(integer::safe<int64_t>(123), Interval::NanosecondTag());
    const auto large = Interval(integer::safe<int64_t>(123), Interval::SecondTag());

    SUBCASE("equal") {
        CHECK_EQ(negative_small, negative_small);
        CHECK_EQ(zero, zero);
        CHECK_EQ(large, large);
        CHECK_EQ(small, small);
    }

    SUBCASE("not equal") {
        CHECK_NE(negative_small, zero);
        CHECK_NE(negative_small, small);
        CHECK_NE(negative_small, large);

        CHECK_NE(large, zero);
        CHECK_NE(zero, large);

        CHECK_NE(small, zero);
        CHECK_NE(zero, small);

        CHECK_NE(small, large);
        CHECK_NE(large, small);
    }

    SUBCASE("less then") {
        CHECK_LT(negative_small, zero);
        CHECK_LT(zero, small);
        CHECK_LT(zero, large);
        CHECK_LT(small, large);
    }

    SUBCASE("less equal") {
        CHECK_LE(negative_small, negative_small);
        CHECK_LE(negative_small, zero);
        CHECK_LE(zero, zero);
        CHECK_LE(zero, small);
        CHECK_LE(zero, large);
        CHECK_LE(small, small);
        CHECK_LE(negative_small, small);
        CHECK_LE(small, large);
        CHECK_LE(large, large);
        CHECK_LE(negative_small, large);
    }

    SUBCASE("greater then") {
        CHECK_GT(zero, negative_small);
        CHECK_GT(small, zero);
        CHECK_GT(large, zero);
        CHECK_GT(large, small);
    }

    SUBCASE("greater equal") {
        CHECK_GE(negative_small, negative_small);
        CHECK_GE(zero, zero);
        CHECK_GE(small, zero);
        CHECK_GE(large, zero);
        CHECK_GE(small, negative_small);
        CHECK_GE(small, small);
        CHECK_GE(large, small);
        CHECK_GE(large, large);
        CHECK_GE(large, negative_small);
    }
}

TEST_CASE("sum") {
    CHECK_EQ(Interval() + Interval(), Interval());
    CHECK_EQ(Interval(2.5, Interval::SecondTag()) + Interval(), Interval(2.5, Interval::SecondTag()));
    CHECK_EQ(Interval(2.5, Interval::SecondTag()) + Interval(2.5, Interval::SecondTag()),
             Interval(5, Interval::SecondTag()));
    CHECK_EQ(Interval(2.5, Interval::SecondTag()) + Interval(-2.5, Interval::SecondTag()), Interval());
}

TEST_CASE("difference") {
    CHECK_EQ(Interval() - Interval(), Interval());
    CHECK_EQ(Interval(2.5, Interval::SecondTag()) - Interval(), Interval(2.5, Interval::SecondTag()));
    CHECK_EQ(Interval(2.5, Interval::SecondTag()) - Interval(2.5, Interval::SecondTag()), Interval());
    CHECK_EQ(Interval(2.5, Interval::SecondTag()) - Interval(-2.5, Interval::SecondTag()),
             Interval(5, Interval::SecondTag()));
}

TEST_CASE("multiple") {
    CHECK_EQ(Interval() * integer::safe<int64_t>(2), Interval());
    CHECK_EQ(Interval(-3, Interval::SecondTag()) * integer::safe<int64_t>(2), Interval(-6, Interval::SecondTag()));
    CHECK_EQ(Interval() * integer::safe<int64_t>(2), Interval());
    CHECK_EQ(Interval(-3, Interval::SecondTag()) * integer::safe<uint64_t>(2), Interval(-6, Interval::SecondTag()));

    CHECK_EQ(Interval() * integer::safe<uint64_t>(2), Interval());
    CHECK_EQ(Interval(-3, Interval::SecondTag()) * integer::safe<uint64_t>(2), Interval(-6, Interval::SecondTag()));
    CHECK_EQ(Interval() * integer::safe<uint64_t>(2), Interval());
    CHECK_EQ(Interval(-3, Interval::SecondTag()) * integer::safe<uint64_t>(2), Interval(-6, Interval::SecondTag()));

    CHECK_EQ(Interval() * 0.5, Interval());
    CHECK_EQ(Interval(-3, Interval::SecondTag()) * 0.5, Interval(-1.5, Interval::SecondTag()));
    CHECK_EQ(Interval() * 0.5, Interval());
    CHECK_EQ(Interval(-3, Interval::SecondTag()) * 0.5, Interval(-1.5, Interval::SecondTag()));
}

TEST_CASE("bool") {
    CHECK_EQ(static_cast<bool>(Interval(1, Interval::SecondTag())), true);
    CHECK_EQ(static_cast<bool>(Interval(0, Interval::SecondTag())), false);
    CHECK_EQ(static_cast<bool>(Interval()), false);
}

TEST_CASE("string") {
    CHECK_EQ(std::string(Interval()), "0.000000s");
    CHECK_EQ(std::string(Interval(integer::safe<uint64_t>(123), Interval::NanosecondTag())), "0.000000s");
    CHECK_EQ(std::string(Interval(integer::safe<uint64_t>(123), Interval::SecondTag()) * 1e-6), "0.000123s");
    CHECK_EQ(std::string(Interval(integer::safe<uint64_t>(123), Interval::SecondTag())), "123.000000s");
}

TEST_SUITE_END();
