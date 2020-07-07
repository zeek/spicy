// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <bitset>
#include <cmath>
#include <limits>

#include <hilti/rt/types/integer.h>

using namespace hilti::rt;

TEST_SUITE_BEGIN("Integer");

TEST_CASE("flip16") {
    CHECK_EQ(integer::flip16(0), 256 * 0);
    CHECK_EQ(integer::flip16(1), 256 * 1);
    CHECK_EQ(integer::flip16(2), 256 * 2);
    CHECK_EQ(integer::flip16(3), 256 * 3);

    const auto max = std::numeric_limits<uint16_t>::max();

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

    CHECK_EQ(integer::flip32(max / 2), std::pow(uint64_t(256), 4) - 256 / 2 - 1);

    CHECK_EQ(integer::flip32(max - 3), std::pow(uint64_t(256), 4) - std::pow(256, 3) * 3 - 1);
    CHECK_EQ(integer::flip32(max - 2), std::pow(uint64_t(256), 4) - std::pow(256, 3) * 2 - 1);
    CHECK_EQ(integer::flip32(max - 1), std::pow(uint64_t(256), 4) - std::pow(256, 3) * 1 - 1);
    CHECK_EQ(integer::flip32(max - 0), std::pow(uint64_t(256), 4) - std::pow(256, 3) * 0 - 1);
}

TEST_CASE("flip64") {
    CHECK_EQ(integer::flip64(0), 0);
    CHECK_EQ(integer::flip64(1), std::pow(uint64_t(256), 7) * 1);
    CHECK_EQ(integer::flip64(2), std::pow(256, 7) * 2);
    CHECK_EQ(integer::flip64(3), std::pow(256, 7) * 3);

    const auto max = std::numeric_limits<uint32_t>::max();

    CHECK_EQ(integer::flip64(max / 2), 18446743519658770432ULL);

    CHECK_EQ(integer::flip64(max - 3), 18230571287300800512ULL);
    CHECK_EQ(integer::flip64(max - 2), 18302628881338728448ULL);
    CHECK_EQ(integer::flip64(max - 1), 18374686475376656384ULL);
    CHECK_EQ(integer::flip64(max - 0), 18446744069414584320ULL);
}

TEST_SUITE_END();
