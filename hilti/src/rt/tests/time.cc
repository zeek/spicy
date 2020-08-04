// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <ctime>
#include <limits>

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

TEST_SUITE_END();
