// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <cstdint>

#include <hilti/rt/libhilti.h>

using namespace hilti::rt;

TEST_CASE("to_string") {
    SUBCASE("primitive") {
        CHECK_EQ(to_string(true), "True");
        CHECK_EQ(to_string(false), "False");
        CHECK_EQ(to_string(-1), "-1");
        CHECK_EQ(to_string(0), "0");
        CHECK_EQ(to_string(1), "1");
        CHECK_EQ(to_string(2), "2");
        CHECK_EQ(to_string(1.5), "1.5");
        CHECK_EQ(to_string(1.5), "1.5");
        CHECK_EQ(to_string("abc"), "\"abc\"");
    }

    SUBCASE("safe-int") {
        using integer::safe;
        CHECK_EQ(to_string(safe<int8_t>(-1)), "-1");
        CHECK_EQ(to_string(safe<char>(-1)), "-1");
    }

    SUBCASE("string") { CHECK_EQ(to_string(std::string("abc")), "\"abc\""); }

    SUBCASE("vector") {
        CHECK_EQ(to_string(std::vector<int8_t>()), "[]");
        CHECK_EQ(to_string(std::vector{int8_t{1}}), "[1]");
        CHECK_EQ(to_string(std::vector{int8_t{1}, 2}), "[1, 2]");
        CHECK_EQ(to_string(std::vector{std::vector{int8_t{1}, 2}}), "[1, 2]");
    }

    SUBCASE("optional") {
        CHECK_EQ(to_string(std::optional<int8_t>()), "(not set)");
        CHECK_EQ(to_string(std::optional<int8_t>(2)), "2");
        CHECK_EQ(to_string(std::optional<std::optional<int8_t>>()), "(not set)");
        CHECK_EQ(to_string(std::optional<std::optional<int8_t>>(2)), "2");
    }
}
