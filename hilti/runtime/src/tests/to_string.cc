// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <cstdint>
#include <string_view>
#include <tuple>

#include <hilti/rt/extension-points.h>
#include <hilti/rt/libhilti.h>
#include <hilti/rt/types/address.h>
#include <hilti/rt/types/bool.h>
#include <hilti/rt/types/bytes.h>
#include <hilti/rt/types/error.h>
#include <hilti/rt/types/integer.h>
#include <hilti/rt/types/interval.h>
#include <hilti/rt/types/map.h>
#include <hilti/rt/types/null.h>
#include <hilti/rt/types/optional.h>
#include <hilti/rt/types/port.h>
#include <hilti/rt/types/regexp.h>
#include <hilti/rt/types/set.h>
#include <hilti/rt/types/stream.h>
#include <hilti/rt/types/time.h>
#include <hilti/rt/types/tuple.h>
#include <hilti/rt/types/vector.h>
#include <hilti/rt/util.h>

using namespace hilti::rt;

inline auto operator""_p(const char* str, size_t size) { return hilti::rt::regexp::Pattern(std::string(str, size)); }

TEST_SUITE_BEGIN("to_string");

TEST_CASE("any") { CHECK_EQ(to_string(hilti::rt::any()), "<any value>"); }

TEST_CASE("primitive") {
    CHECK_EQ(to_string(true), "True");
    CHECK_EQ(to_string(false), "False");
    CHECK_EQ(to_string(-1), "-1");
    CHECK_EQ(to_string(0), "0");
    CHECK_EQ(to_string(1), "1");
    CHECK_EQ(to_string(2), "2");
    CHECK_EQ(to_string(1.5), "1.5");
    CHECK_EQ(to_string(1.5), "1.5");

    CHECK_EQ(to_string(static_cast<int8_t>(-42)), "-42");
    CHECK_EQ(to_string(static_cast<uint8_t>(42)), "42");
    CHECK_EQ(to_string(static_cast<int16_t>(-42)), "-42");
    CHECK_EQ(to_string(static_cast<uint16_t>(42)), "42");
    CHECK_EQ(to_string(static_cast<int32_t>(-42)), "-42");
    CHECK_EQ(to_string(static_cast<uint32_t>(42)), "42");
    CHECK_EQ(to_string(static_cast<int64_t>(-42)), "-42");
    CHECK_EQ(to_string(static_cast<uint64_t>(42)), "42");

    CHECK_EQ(to_string("abc"), "\"abc\"");
}

TEST_CASE("safe-int") {
    using integer::safe;
    CHECK_EQ(to_string(safe<int8_t>(-42)), "-42");
    CHECK_EQ(to_string(safe<char>(42)), "42");

    CHECK_EQ(to_string(safe<uint16_t>(42)), "42");
    CHECK_EQ(to_string(safe<int16_t>(-42)), "-42");
    CHECK_EQ(to_string(safe<uint32_t>(42)), "42");
    CHECK_EQ(to_string(safe<int32_t>(-42)), "-42");
    CHECK_EQ(to_string(safe<uint64_t>(42)), "42");
    CHECK_EQ(to_string(safe<int64_t>(-42)), "-42");
}

TEST_CASE("string") {
    CHECK_EQ(to_string(std::string("abc")), "\"abc\"");
    CHECK_EQ(to_string_for_print(std::string("abc")), "abc");
}

TEST_CASE("string_view") {
    CHECK_EQ(to_string(std::string_view("abc")), "\"abc\"");
    CHECK_EQ(to_string_for_print(std::string_view("abc")), "abc");
}

TEST_CASE("Address") {
    CHECK_EQ(to_string(Address()), "<bad address>");
    CHECK_EQ(to_string(Address("127.0.0.1")), "127.0.0.1");
    CHECK_EQ(to_string(Address("2001:db8:85a3:8d3:1319:8a2e:370:7348")), "2001:db8:85a3:8d3:1319:8a2e:370:7348");

    CHECK_EQ(fmt("%s", Address()), "<bad address>");
    CHECK_EQ(fmt("%s", Address("127.0.0.1")), "127.0.0.1");
    CHECK_EQ(fmt("%s", Address("2001:db8:85a3:8d3:1319:8a2e:370:7348")), "2001:db8:85a3:8d3:1319:8a2e:370:7348");
}

TEST_CASE("AddressFamily") {
    CHECK_EQ(to_string(Enum(AddressFamily::IPv4)), "AddressFamily::IPv4");
    CHECK_EQ(to_string(Enum(AddressFamily::IPv6)), "AddressFamily::IPv6");
    CHECK_EQ(to_string(Enum(AddressFamily::Undef)), "AddressFamily::Undef");

    CHECK_EQ(fmt("%s", Enum(AddressFamily::IPv4)), "AddressFamily::IPv4");
    CHECK_EQ(fmt("%s", Enum(AddressFamily::IPv6)), "AddressFamily::IPv6");
    CHECK_EQ(fmt("%s", Enum(AddressFamily::Undef)), "AddressFamily::Undef");
}

TEST_CASE("Bool") {
    CHECK_EQ(to_string(Bool(true)), "True");
    CHECK_EQ(to_string(Bool(false)), "False");
}

TEST_CASE("integer::BitOrder") {
    CHECK_EQ(to_string(Enum(integer::BitOrder::LSB0)), "BitOrder::LSB0");
    CHECK_EQ(to_string(Enum(integer::BitOrder::MSB0)), "BitOrder::MSB0");
    CHECK_EQ(to_string(Enum(integer::BitOrder::Undef)), "BitOrder::Undef");
}

TEST_CASE("bytes::Charset") {
    CHECK_EQ(to_string(Enum(unicode::Charset::ASCII)), "Charset::ASCII");
    CHECK_EQ(to_string(Enum(unicode::Charset::UTF8)), "Charset::UTF8");
    CHECK_EQ(to_string(Enum(unicode::Charset::UTF16BE)), "Charset::UTF16BE");
    CHECK_EQ(to_string(Enum(unicode::Charset::UTF16LE)), "Charset::UTF16LE");
    CHECK_EQ(to_string(Enum(unicode::Charset::Undef)), "Charset::Undef");
}

TEST_CASE("unicode::DecodeErrorStrategy") {
    CHECK_EQ(to_string(Enum(unicode::DecodeErrorStrategy::IGNORE)), "DecodeErrorStrategy::IGNORE");
    CHECK_EQ(to_string(Enum(unicode::DecodeErrorStrategy::REPLACE)), "DecodeErrorStrategy::REPLACE");
    CHECK_EQ(to_string(Enum(unicode::DecodeErrorStrategy::STRICT)), "DecodeErrorStrategy::STRICT");
}

TEST_CASE("bytes::Side") {
    CHECK_EQ(to_string(Enum(bytes::Side::Left)), "Side::Left");
    CHECK_EQ(to_string(Enum(bytes::Side::Right)), "Side::Right");
    CHECK_EQ(to_string(Enum(bytes::Side::Both)), "Side::Both");
}

TEST_CASE("ByteOrder") {
    CHECK_EQ(to_string(Enum(ByteOrder::Little)), "ByteOrder::Little");
    CHECK_EQ(to_string(Enum(ByteOrder::Big)), "ByteOrder::Big");
    CHECK_EQ(to_string(Enum(ByteOrder::Network)), "ByteOrder::Network");
    CHECK_EQ(to_string(Enum(ByteOrder::Host)), "ByteOrder::Host");
    CHECK_EQ(to_string(Enum(ByteOrder::Undef)), "ByteOrder::Undef");
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

    CHECK_EQ(fmt("%s", result::Error("could not foo the bar")), "could not foo the bar");
}

TEST_CASE("Exception") { CHECK_EQ(to_string(UsageError("my error")), "<exception: my error>"); }

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
    CHECK_EQ(to_string(hilti::rt::Optional<int8_t>()), "(not set)");
    CHECK_EQ(to_string(hilti::rt::Optional<int8_t>(2)), "2");
    CHECK_EQ(to_string(hilti::rt::Optional<hilti::rt::Optional<int8_t>>()), "(not set)");
    CHECK_EQ(to_string(hilti::rt::Optional<hilti::rt::Optional<int8_t>>(2)), "2");
    CHECK_EQ(to_string(hilti::rt::Optional<std::string>("abc")), "\"abc\"");

    CHECK_EQ(to_string_for_print(hilti::rt::Optional<int8_t>(2)), "2");
    CHECK_EQ(to_string_for_print(hilti::rt::Optional<std::string>("abc")), "abc");
    CHECK_EQ(to_string_for_print(hilti::rt::Optional<std::string>()), "(not set)");
    CHECK_EQ(to_string_for_print(hilti::rt::Optional<std::string_view>("abc")), "abc");
    CHECK_EQ(to_string_for_print(hilti::rt::Optional<std::string_view>()), "(not set)");

    hilti::rt::Optional<Port> port1{"123/tcp"};
    hilti::rt::Optional<Port> port2{};

    CHECK_EQ(to_string(port1), "123/tcp");
    CHECK_EQ(to_string(port2), "(not set)");

    std::stringstream x;
    x << port1 << " " << port2;
    CHECK_EQ(x.str(), "123/tcp (not set)");
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
    CHECK_EQ(to_string(*Map<uint32_t, uint32_t>({{1, 11}, {2, 22}, {3, 33}}).begin()), "(1, 11)");
}

TEST_CASE("null") {
    CHECK_EQ(to_string(Null()), "Null");
    CHECK_EQ(fmt("%s", Null()), "Null");
}

TEST_CASE("Port") {
    CHECK_EQ(to_string(Port()), "0/<unknown>");
    CHECK_EQ(to_string(Port(1234, Protocol::TCP)), "1234/tcp");
    CHECK_EQ(to_string(Port(1234, Protocol::UDP)), "1234/udp");
    CHECK_EQ(to_string(Port(1234, Protocol::ICMP)), "1234/icmp");
    CHECK_EQ(to_string(Port(1234, Protocol::Undef)), "1234/<unknown>");

    CHECK_EQ(fmt("%s", Port()), "0/<unknown>");
    CHECK_EQ(fmt("%s", Port(1234, Protocol::TCP)), "1234/tcp");
    CHECK_EQ(fmt("%s", Port(1234, Protocol::UDP)), "1234/udp");
    CHECK_EQ(fmt("%s", Port(1234, Protocol::ICMP)), "1234/icmp");
    CHECK_EQ(fmt("%s", Port(1234, Protocol::Undef)), "1234/<unknown>");
}

TEST_CASE("Protocol") {
    CHECK_EQ(to_string(Enum(Protocol::TCP)), "TCP");
    CHECK_EQ(to_string(Enum(Protocol::UDP)), "UDP");
    CHECK_EQ(to_string(Enum(Protocol::ICMP)), "ICMP");
    CHECK_EQ(to_string(Enum(Protocol::Undef)), "<unknown protocol>");

    CHECK_EQ(fmt("%s", Enum(Protocol::TCP)), "TCP");
    CHECK_EQ(fmt("%s", Enum(Protocol::UDP)), "UDP");
    CHECK_EQ(fmt("%s", Enum(Protocol::ICMP)), "ICMP");
    CHECK_EQ(fmt("%s", Enum(Protocol::Undef)), "<unknown protocol>");
}

TEST_CASE("real::Type") {
    CHECK_EQ(to_string(Enum(real::Type::IEEE754_Double)), "Type::IEEE754_Double");
    CHECK_EQ(to_string(Enum(real::Type::IEEE754_Single)), "Type::IEEE754_Single");
    CHECK_EQ(to_string(Enum(real::Type::Undef)), "Type::Undef");
}

TEST_CASE("RegExp") {
    CHECK_EQ(to_string(RegExp()), "<regexp w/o pattern>");
    CHECK_EQ(to_string(RegExp({"a"}, regexp::Flags())), "/a/");
    CHECK_EQ(to_string(RegExp({"a"}, regexp::Flags({.no_sub = 1}))), "/a/ &nosub");
    CHECK_EQ(to_string(RegExp({"a"}, regexp::Flags())), "/a/");
    CHECK_EQ(to_string(RegExp({regexp::Pattern{"a"}, regexp::Pattern{"b"}}, regexp::Flags())), "/a/ | /b/");

    CHECK_EQ(to_string(RegExp({"/"}, regexp::Flags())), "///");

    CHECK_EQ(to_string(RegExp({""}, regexp::Flags()).tokenMatcher()), "<regexp-match-state>");

    std::stringstream x;
    x << RegExp({"X"});
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

    SUBCASE("safe-iterator") {
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

    SUBCASE("unsafe-iterator") {
        CHECK_EQ(to_string(Stream("0123456789"_b).unsafeBegin()), "<offset=0 data=b\"0123456789\">");
        CHECK_EQ(to_string(Stream("01234567890123456789"_b).unsafeBegin()), "<offset=0 data=b\"0123456789\"...>");
        CHECK_EQ(to_string(Stream("01234567890123456789"_b).unsafeEnd()), "<offset=20 data=b\"\">");
    }
}

TEST_CASE("Time") {
    CHECK_EQ(to_string(Time()), "<not set>");
    CHECK_EQ(to_string(Time(0, Time::NanosecondTag())), "<not set>");
    CHECK_EQ(to_string(Time(0, Time::SecondTag())), "<not set>");

    CHECK_EQ(to_string(Time(integer::safe<uint64_t>(1), Time::NanosecondTag())), "1970-01-01T00:00:00.000000001Z");
    CHECK_EQ(to_string(Time(1, Time::SecondTag())), "1970-01-01T00:00:01.000000000Z");

    CHECK_EQ(fmt("%s", Time(1, Time::SecondTag())), "1970-01-01T00:00:01.000000000Z");
}

TEST_CASE("tuple") {
    CHECK_EQ(to_string(tuple::make(1, std::string("abc"), 1e-9)), "(1, \"abc\", 1e-09)");
    CHECK_EQ(fmt("%s", tuple::make(1, std::string("abc"), 1e-9)), "(1, \"abc\", 1e-09)");
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
