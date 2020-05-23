// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <cstdint>

#include <hilti/rt/libhilti.h>
#include <hilti/rt/types/bytes.h>
#include <hilti/rt/types/integer.h>
#include <hilti/rt/types/list.h>
#include <hilti/rt/types/map.h>
#include <hilti/rt/types/regexp.h>
#include <hilti/rt/types/set.h>
#include <hilti/rt/types/time.h>
#include <hilti/rt/types/vector.h>

using namespace hilti::rt;

TEST_SUITE_BEGIN("to_string");

TEST_CASE("primitive") {
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

TEST_CASE("safe-int") {
    using integer::safe;
    CHECK_EQ(to_string(safe<int8_t>(-1)), "-1");
    CHECK_EQ(to_string(safe<char>(-1)), "-1");
}

TEST_CASE("string") { CHECK_EQ(to_string(std::string("abc")), "\"abc\""); }

TEST_CASE("Vector") {
    CHECK_EQ(to_string(vector::Empty()), "[]");

    CHECK_EQ(to_string(Vector<int8_t>()), "[]");
    CHECK_EQ(to_string(Vector<int8_t>({1})), "[1]");
    CHECK_EQ(to_string(Vector<int8_t>({1, 2})), "[1, 2]");
    CHECK_EQ(to_string(Vector<Vector<int8_t>>({{1, 2}})), "[[1, 2]]");

    CHECK_EQ(to_string(Vector<Vector<int8_t>>({{1, 2}}).begin()), "<vector iterator>");
    CHECK_EQ(to_string(Vector<Vector<int8_t>>({{1, 2}}).cbegin()), "<const vector iterator>");
}

TEST_CASE("optional") {
    CHECK_EQ(to_string(std::optional<int8_t>()), "(not set)");
    CHECK_EQ(to_string(std::optional<int8_t>(2)), "2");
    CHECK_EQ(to_string(std::optional<std::optional<int8_t>>()), "(not set)");
    CHECK_EQ(to_string(std::optional<std::optional<int8_t>>(2)), "2");
}

TEST_CASE("Set") {
    CHECK_EQ(to_string(set::Empty()), "{}");
    CHECK_EQ(to_string(Set<int>()), "{}");
    CHECK_EQ(to_string(Set<int>({1})), "{1}");
    CHECK_EQ(to_string(Set<int>({1, 2, 3})), "{1, 2, 3}");
}

TEST_CASE("Map") {
    CHECK_EQ(to_string(map::Empty()), "{}");
    CHECK_EQ(to_string(Map<int, int>()), "{}");
    CHECK_EQ(to_string(Map<int, Bytes>({{1, "abc"_b}})), "{1: b\"abc\"}");
    CHECK_EQ(to_string(Map<int, Bytes>({{1, "abc"_b}, {2, "def"_b}})), "{1: b\"abc\", 2: b\"def\"}");
}

TEST_CASE("List") {
    CHECK_EQ(to_string(list::Empty()), "[]");
    CHECK_EQ(to_string(List<int>()), "[]");
    CHECK_EQ(to_string(List<int>({1, 2, 3})), "[1, 2, 3]");
    CHECK_EQ(to_string(List<List<int>>({{1, 2, 3}, {1, 2}})), "[[1, 2, 3], [1, 2]]");
    CHECK_EQ(to_string(List<Bytes>({"abc"_b})), "[b\"abc\"]");
}

TEST_CASE("RegExp") {
    CHECK_EQ(to_string(RegExp()), "<regexp w/o pattern>");
    CHECK_EQ(to_string(RegExp("a", regexp::Flags())), "/a/");
    CHECK_EQ(to_string(RegExp("a", regexp::Flags({.no_sub = 1}))), "/a/ &nosub");
    CHECK_EQ(to_string(RegExp(std::vector<std::string>({"a"}), regexp::Flags())), "/a/ &nosub");
    CHECK_EQ(to_string(RegExp(std::vector<std::string>({"a", "b"}), regexp::Flags())), "/a/ | /b/ &nosub");

    CHECK_EQ(to_string(RegExp("/", regexp::Flags())), "///");

    CHECK_EQ(to_string(RegExp("", regexp::Flags()).tokenMatcher()), "<regexp-match-state>");
}

TEST_CASE("Time") {
    CHECK_EQ(to_string(Time()), "<not set>");
    CHECK_EQ(to_string(Time(uint64_t(0))), "<not set>");
    CHECK_EQ(to_string(Time(double(0))), "<not set>");

    CHECK_EQ(to_string(Time(uint64_t(1))), "1970-01-01T00:00:00.000000001Z");
}

TEST_SUITE_END();
