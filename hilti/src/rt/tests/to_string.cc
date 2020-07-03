// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <cstdint>

#include <hilti/rt/libhilti.h>
#include <hilti/rt/types/bool.h>
#include <hilti/rt/types/bytes.h>
#include <hilti/rt/types/error.h>
#include <hilti/rt/types/integer.h>
#include <hilti/rt/types/interval.h>
#include <hilti/rt/types/map.h>
#include <hilti/rt/types/port.h>
#include <hilti/rt/types/regexp.h>
#include <hilti/rt/types/set.h>
#include <hilti/rt/types/stream.h>
#include <hilti/rt/types/time.h>
#include <hilti/rt/types/vector.h>
#include <hilti/rt/util.h>

using namespace hilti::rt;

TEST_SUITE_BEGIN("to_string");

TEST_CASE("any") { CHECK_EQ(to_string(std::any()), "<any value>"); }

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

TEST_CASE("Bool") {
    CHECK_EQ(to_string(Bool(true)), "True");
    CHECK_EQ(to_string(Bool(false)), "False");
}

TEST_CASE("Bytes") {
    CHECK_EQ(to_string("ABC"_b), "b\"ABC\"");
    CHECK_EQ(to_string("\0\2\3\0\6\7A\01"_b), "b\"\\x00\\x02\\x03\\x00\\x06\\x07A\\x01\"");
    CHECK_EQ(fmt("%s", "\0\2\3\0\6\7A\01"_b), "\\x00\\x02\\x03\\x00\\x06\\x07A\\x01");

    CHECK_EQ(to_string_for_print("ABC"_b), "ABC");
    CHECK_EQ(to_string_for_print("\0\2\3\0\6\7A\01"_b), "\\x00\\x02\\x03\\x00\\x06\\x07A\\x01");

    CHECK_EQ(to_string("ABC"_b.begin()), "<bytes iterator>");
    CHECK_EQ(fmt("%s", "ABC"_b.begin()), "<bytes iterator>");
}

TEST_CASE("Error") {
    CHECK_EQ(to_string(result::Error()), "<error: <no description>>");
    CHECK_EQ(to_string(result::Error("")), "<error>");
    CHECK_EQ(to_string(result::Error("could not foo the bar")), "<error: could not foo the bar>");
}

TEST_CASE("Exception") { CHECK_EQ(to_string(Exception("my error")), "<exception: my error>"); }

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

TEST_CASE("Interval") {
    CHECK_EQ(to_string(Interval(integer::safe<uint64_t>(123), Interval::SecondTag())), "123.000000s");
    CHECK_EQ(fmt("%s", Interval(integer::safe<uint64_t>(123), Interval::SecondTag())), "123.000000s");
}

TEST_CASE("Map") {
    CHECK_EQ(to_string(map::Empty()), "{}");
    CHECK_EQ(to_string(Map<int, int>()), "{}");
    CHECK_EQ(to_string(Map<int, Bytes>({{1, "abc"_b}})), "{1: b\"abc\"}");
    CHECK_EQ(to_string(Map<int, Bytes>({{1, "abc"_b}, {2, "def"_b}})), "{1: b\"abc\", 2: b\"def\"}");
}

TEST_CASE("Port") {
    CHECK_EQ(to_string(Port()), "0/<unknown>");
    CHECK_EQ(to_string(Port(1234, Protocol::TCP)), "1234/tcp");
    CHECK_EQ(to_string(Port(1234, Protocol::UDP)), "1234/udp");
    CHECK_EQ(to_string(Port(1234, Protocol::ICMP)), "1234/icmp");
    CHECK_EQ(to_string(Port(1234, Protocol::Undef)), "1234/<unknown>");
}

TEST_CASE("Protocol") {
    CHECK_EQ(to_string(Protocol::TCP), "Protocol::TCP");
    CHECK_EQ(to_string(Protocol::UDP), "Protocol::UDP");
    CHECK_EQ(to_string(Protocol::ICMP), "Protocol::ICMP");
    CHECK_EQ(to_string(Protocol::Undef), "<unknown protocol>");
}

TEST_CASE("RegExp") {
    CHECK_EQ(to_string(RegExp()), "<regexp w/o pattern>");
    CHECK_EQ(to_string(RegExp("a", regexp::Flags())), "/a/");
    CHECK_EQ(to_string(RegExp("a", regexp::Flags({.no_sub = 1}))), "/a/ &nosub");
    CHECK_EQ(to_string(RegExp(std::vector<std::string>({"a"}), regexp::Flags())), "/a/ &nosub");
    CHECK_EQ(to_string(RegExp(std::vector<std::string>({"a", "b"}), regexp::Flags())), "/a/ | /b/ &nosub");

    CHECK_EQ(to_string(RegExp("/", regexp::Flags())), "///");

    CHECK_EQ(to_string(RegExp("", regexp::Flags()).tokenMatcher()), "<regexp-match-state>");

    std::stringstream x;
    x << RegExp("X");
    CHECK_EQ(x.str(), "/X/");
}

TEST_CASE("Set") {
    CHECK_EQ(to_string(set::Empty()), "{}");
    CHECK_EQ(to_string(Set<int>()), "{}");
    CHECK_EQ(to_string(Set<int>({1})), "{1}");
    CHECK_EQ(to_string(Set<int>({1, 2, 3})), "{1, 2, 3}");
}

TEST_CASE("Stream") {
    CHECK_EQ(to_string(Stream()), "b\"\"");
    CHECK_EQ(to_string(Stream("Gänsefüßchen\x00\x01\x02"_b)),
             "b\"G\\xc3\\xa4nsef\\xc3\\xbc\\xc3\\x9fchen\\x00\\x01\\x02\"");
    CHECK_EQ(to_string_for_print(Stream("Gänsefüßchen\x00\x01\x02"_b)),
             "G\\xc3\\xa4nsef\\xc3\\xbc\\xc3\\x9fchen\\x00\\x01\\x02");

    CHECK_EQ(fmt("%s", Stream()), "");
    CHECK_EQ(fmt("%s", Stream("Gänsefüßchen\x00\x01\x02"_b)), "G\\xc3\\xa4nsef\\xc3\\xbc\\xc3\\x9fchen\\x00\\x01\\x02");

    SUBCASE("iterator") {
        CHECK_EQ(to_string(Stream("0123456789"_b).begin()), "<offset=0 data=b\"0123456789\">");
        CHECK_EQ(to_string(Stream("01234567890123456789"_b).begin()), "<offset=0 data=b\"0123456789\"...>");
        CHECK_EQ(to_string(Stream("01234567890123456789"_b).end()), "<offset=20 data=b\"\">");
        CHECK_EQ(to_string(stream::SafeConstIterator()), "<uninitialized>");
        CHECK_EQ(to_string([]() {
                     auto s = Stream();
                     return s.begin();
                 }()),
                 "<expired>");
    }
}

TEST_CASE("Time") {
    CHECK_EQ(to_string(Time()), "<not set>");
    CHECK_EQ(to_string(Time(0, Time::NanosecondTag())), "<not set>");
    CHECK_EQ(to_string(Time(0, Time::SecondTag())), "<not set>");

    CHECK_EQ(to_string(Time(integer::safe<uint64_t>(1), Time::NanosecondTag())), "1970-01-01T00:00:00.000000001Z");
    CHECK_EQ(to_string(Time(1, Time::SecondTag())), "1970-01-01T00:00:01.000000000Z");
}

TEST_CASE("View") {
    CHECK_EQ(to_string(Stream().view()), "b\"\"");
    CHECK_EQ(to_string(Stream("Gänsefüßchen\x00\x01\x02"_b).view()),
             "b\"G\\xc3\\xa4nsef\\xc3\\xbc\\xc3\\x9fchen\\x00\\x01\\x02\"");
    CHECK_EQ(to_string_for_print(Stream("Gänsefüßchen\x00\x01\x02"_b).view()),
             "G\\xc3\\xa4nsef\\xc3\\xbc\\xc3\\x9fchen\\x00\\x01\\x02");

    CHECK_EQ(fmt("%s", Stream().view()), "");
    CHECK_EQ(fmt("%s", Stream("Gänsefüßchen\x00\x01\x02"_b).view()),
             "G\\xc3\\xa4nsef\\xc3\\xbc\\xc3\\x9fchen\\x00\\x01\\x02");
}

TEST_SUITE_END();
