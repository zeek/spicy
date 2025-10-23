// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <ctime>
#include <limits>

#include <hilti/rt/types/interval.h>
#include <hilti/rt/types/time.h>

using namespace hilti::rt;

TEST_SUITE_BEGIN("time");

TEST_CASE("current_time") {
    const auto start = std::time(nullptr);
    const auto current_time = time::current_time();
    const auto end = std::time(nullptr);

    // We shift `start` and `end` by one second to account for possible precision
    // mismatch and resulting rounding errors and use of different clocks.
    CHECK_LE(start - 1, current_time.seconds());

    // NOTE: This test could flake if the clock is adjusted after `start` has been taken.
    CHECK_GE(end + 1, current_time.seconds());
}

TEST_CASE("mktime") {
    setenv("TZ", "", 1);
    tzset();
    const auto t = time::mktime(2021, 4, 1, 1, 2, 3);
    CHECK_EQ(t, Time(1617238923, Time::SecondTag{}));

    CHECK_THROWS_AS(time::mktime(42, 4, 1, 1, 2, 3), const InvalidValue&);
    CHECK_THROWS_AS(time::mktime(2021, 4, 1, 1, 2, 100), const InvalidValue&);
}

TEST_SUITE_BEGIN("Time");

TEST_CASE("comparisons") {
    const auto t0 = Time(0, Time::NanosecondTag{});
    const auto t1 = Time(1, Time::NanosecondTag{});

    CHECK_EQ(t0, t0);
    CHECK_EQ(t1, t1);

    CHECK_NE(t0, t1);
    CHECK_NE(t1, t0);

    CHECK_LT(t0, t1);
    CHECK_LE(t0, t1);
    CHECK_LE(t0, t0);

    CHECK_GT(t1, t0);
    CHECK_GE(t1, t0);
    CHECK_GE(t1, t1);
}

TEST_CASE("operator+") {
    CHECK_EQ(Time(1, Time::NanosecondTag{}) + Interval(0, Interval::SecondTag{}), Time(1, Time::NanosecondTag{}));
    CHECK_EQ(Time(1, Time::NanosecondTag{}) + Interval(1, Interval::NanosecondTag{}), Time(2, Time::NanosecondTag{}));
    CHECK_EQ(Time(1, Time::SecondTag{}) + Interval(1, Interval::SecondTag{}), Time(2, Time::SecondTag{}));

    CHECK_THROWS_WITH_AS(Time(std::numeric_limits<uint64_t>::max(), Time::NanosecondTag{}) +
                             Interval(std::numeric_limits<uint64_t>::max(), Interval::NanosecondTag{}),
                         "integer overflow", const Overflow&);

    CHECK_THROWS_WITH_AS(Time(0, Time::NanosecondTag{}) + Interval(-1, Interval::NanosecondTag{}),
                         "operation yielded negative time 0 -1", const RuntimeError&);
}

TEST_CASE("operator-") {
    SUBCASE("Interval") {
        CHECK_EQ(Time(1, Time::NanosecondTag{}) - Interval(0, Interval::SecondTag{}), Time(1, Time::NanosecondTag{}));
        CHECK_EQ(Time(1, Time::NanosecondTag{}) - Interval(1, Interval::NanosecondTag{}),
                 Time(0, Time::NanosecondTag{}));
        CHECK_EQ(Time(1, Time::SecondTag{}) - Interval(1, Interval::SecondTag{}), Time(0, Time::SecondTag{}));

        CHECK_THROWS_WITH_AS(Time(1, Time::NanosecondTag{}) - Interval(1, Interval::SecondTag{}),
                             "operation yielded negative time", const RuntimeError&);
    }

    SUBCASE("Time") {
        CHECK_EQ(Time(1, Time::NanosecondTag{}) - Time(0, Time::SecondTag{}), Interval(1, Interval::NanosecondTag{}));
        CHECK_EQ(Time(1, Time::NanosecondTag{}) - Time(1, Time::NanosecondTag{}),
                 Interval(0, Interval::NanosecondTag{}));
        CHECK_EQ(Time(1, Time::SecondTag{}) - Time(1, Time::SecondTag{}), Interval(0, Interval::SecondTag{}));
        CHECK_EQ(Time(1, Time::NanosecondTag{}) - Time(10, Time::NanosecondTag{}),
                 Interval(-9, Interval::NanosecondTag{}));
    }
}

TEST_CASE("construct") {
    SUBCASE("default") { CHECK_EQ(Time().nanoseconds(), 0); }

    SUBCASE("from nanoseconds") {
        CHECK_EQ(Time(42, Time::NanosecondTag{}).nanoseconds(), 42);
        CHECK_THROWS_WITH_AS(Time(-1, Time::NanosecondTag{}).nanoseconds(), "integer overflow", const Overflow&);
    }

    SUBCASE("from seconds") {
        CHECK_EQ(Time(42, Time::SecondTag{}).seconds(), 42);
        CHECK_THROWS_WITH_AS(Time(-1, Time::SecondTag{}).seconds(), "value cannot be represented as a time",
                             const RuntimeError&);
        CHECK_THROWS_WITH_AS(Time(1e42, Time::SecondTag{}).seconds(), "value cannot be represented as a time",
                             const RuntimeError&);
    }
}

TEST_CASE("nanoseconds") {
    CHECK_EQ(Time(123, Time::SecondTag{}).nanoseconds(), 123'000'000'000);
    CHECK_EQ(Time(500, Time::NanosecondTag{}).nanoseconds(), 500);
}

TEST_CASE("seconds") {
    CHECK_EQ(Time(123, Time::SecondTag{}).seconds(), 123);
    CHECK_EQ(Time(500'000'000, Time::NanosecondTag{}).seconds(), 0.5);
}

TEST_SUITE_END();

TEST_SUITE_END();
