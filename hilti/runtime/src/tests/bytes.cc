// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <ostream>
#include <tuple>
#include <type_traits>

#include <hilti/rt/exception.h>
#include <hilti/rt/types/bytes.h>
#include <hilti/rt/types/integer.h>
#include <hilti/rt/types/regexp.h>

using namespace std::string_literals;
using namespace hilti::rt;
using namespace hilti::rt::bytes;

TEST_SUITE_BEGIN("Bytes");

TEST_CASE("add") {
    CHECK_EQ("123"_b + "456"_b, "123456"_b);
    CHECK_EQ("123"_b + ""_b, "123"_b);
    CHECK_EQ(""_b + "123"_b, "123"_b);
    CHECK_EQ(""_b + ""_b, ""_b);
}

TEST_CASE("at") {
    const auto b = "123"_b;
    CHECK_EQ(b.at(0), b.begin());
    CHECK_EQ(*b.at(0), '1');
    CHECK_EQ(*b.at(1), '2');
    CHECK_EQ(*b.at(2), '3');
    CHECK_EQ(b.at(3), b.end());
    CHECK_THROWS_WITH_AS(*b.at(5), "index 5 out of bounds", const IndexError&);
}

TEST_CASE("decode") {
    CHECK_EQ("123"_b.decode(unicode::Charset::ASCII), "123");
    CHECK_EQ("abc"_b.decode(unicode::Charset::ASCII), "abc");
    CHECK_EQ("abc"_b.decode(unicode::Charset::UTF8), "abc");
    CHECK_EQ("\xF0\x9F\x98\x85"_b.decode(unicode::Charset::UTF8), "\xF0\x9F\x98\x85");
    CHECK_EQ("\xF0\x9F\x98\x85"_b.decode(unicode::Charset::ASCII), "????");

    CHECK_EQ("€100"_b.decode(unicode::Charset::ASCII, unicode::DecodeErrorStrategy::REPLACE), "???100");
    CHECK_EQ("€100"_b.decode(unicode::Charset::ASCII, unicode::DecodeErrorStrategy::IGNORE), "100");
    CHECK_THROWS_WITH_AS("123ä4"_b.decode(unicode::Charset::ASCII, unicode::DecodeErrorStrategy::STRICT),
                         "illegal ASCII character in string", const RuntimeError&);

    CHECK_EQ("\xc3\x28"_b.decode(unicode::Charset::UTF8, unicode::DecodeErrorStrategy::REPLACE), "\ufffd(");
    CHECK_EQ("\xc3\x28"_b.decode(unicode::Charset::UTF8, unicode::DecodeErrorStrategy::IGNORE), "(");
    CHECK_THROWS_WITH_AS("\xc3\x28"_b.decode(unicode::Charset::UTF8, unicode::DecodeErrorStrategy::STRICT),
                         "illegal UTF8 sequence in string", const RuntimeError&);

    CHECK_EQ(Bytes("\0a\0b\0c"s).decode(unicode::Charset::UTF16BE, unicode::DecodeErrorStrategy::STRICT), "abc");
    CHECK_EQ(Bytes("a\0b\0c\0"s).decode(unicode::Charset::UTF16LE, unicode::DecodeErrorStrategy::STRICT), "abc");

    // Our `decode` of UTF-16 bytes returns UTF8 string with BOM if they do not fit into ASCII, see e.g.,
    // https://stackoverflow.com/questions/2223882/whats-the-difference-between-utf-8-and-utf-8-with-bom.
    // To compute the expected results in Python encode with `utf_8_sig` encoding.
    //
    // LHS is an UTF16 encoding of '東京', RHS UTF8 with BOM.
    CHECK_EQ("\xff\xfeqg\xacN"_b.decode(unicode::Charset ::UTF16LE, unicode::DecodeErrorStrategy::STRICT),
             "\ufeff東京");

    // Decoding of UTF16 with BOM. The byte order in the charset is just a hint, but we still decode as UTF16.
    CHECK_EQ("\xff\xfeqg\xacN"_b.decode(unicode::Charset ::UTF16BE, unicode::DecodeErrorStrategy::STRICT),
             "\ufeff東京");

    // Decoding of too few bytes for UTF16 (expected even number, provided uneven).
    CHECK_THROWS_WITH_AS(Bytes("\0a\0b\0"s).decode(unicode::Charset::UTF16BE, unicode::DecodeErrorStrategy::STRICT),
                         "illegal UTF16 character in string", const RuntimeError&);
    CHECK_EQ(Bytes("\0a\0b\0"s).decode(unicode::Charset::UTF16BE, unicode::DecodeErrorStrategy::IGNORE), "ab");
    CHECK_EQ(Bytes("\0a\0b\0"s).decode(unicode::Charset::UTF16BE, unicode::DecodeErrorStrategy::REPLACE), "ab\ufffd");

    // Our UTF16 implementation seems to differ in what it considers invalid encodings, e.g., `\x00\xd8` is rejected by
    // python-3.1[1-3], but accepted by us.
    //
    // TODO(bbannier): Test rejection of invalid UTF16 (but with even length).
    CHECK_EQ(Bytes("\x00\xd8").decode(unicode::Charset::UTF16LE, unicode::DecodeErrorStrategy::STRICT), "");

    CHECK_THROWS_WITH_AS("123"_b.decode(unicode::Charset::Undef), "unknown character set for decoding",
                         const RuntimeError&);
}

TEST_CASE("extract") {
    SUBCASE("sufficient data") {
        unsigned char dst1[3] = {0};
        CHECK_EQ("123456"_b.extract(dst1, 3), "456"_b);
        CHECK_EQ(dst1[0], '1');
        CHECK_EQ(dst1[1], '2');
        CHECK_EQ(dst1[2], '3');

        unsigned char dst2[3] = {0};
        CHECK_EQ("123"_b.extract(dst2, 3), ""_b);
        CHECK_EQ(dst2[0], '1');
        CHECK_EQ(dst2[1], '2');
        CHECK_EQ(dst2[2], '3');
    }

    SUBCASE("insufficient data") {
        unsigned char dst1[3] = {0};
        // NOLINTNEXTLINE(bugprone-throw-keyword-missing)
        CHECK_THROWS_WITH_AS(""_b.extract(dst1, 3), "insufficient data in source", const InvalidArgument&);

        unsigned char dst2[1] = {0};
        // NOLINTNEXTLINE(bugprone-throw-keyword-missing)
        CHECK_THROWS_WITH_AS(""_b.extract(dst2, 1), "insufficient data in source", const InvalidArgument&);
    }
}

TEST_CASE("comparison") {
    const auto b = "123"_b;

    SUBCASE("equal") {
        CHECK_EQ(b, b);
        CHECK_EQ(Bytes(b), b);
        CHECK_NE("abc"_b, b);
        CHECK_NE(""_b, b);
        CHECK_EQ(""_b, ""_b);
    }

    SUBCASE("less") {
        CHECK_FALSE(operator<(b, b));
        CHECK_LT("123"_b, "124"_b);
        CHECK_FALSE(operator<("124"_b, "123"_b));
        CHECK_LT("12"_b, "123"_b);
        CHECK_FALSE(operator<("123"_b, "12"_b));
    }

    SUBCASE("less equal") {
        CHECK_LE(b, b);
        CHECK_LE("123"_b, "124"_b);
        CHECK_FALSE(operator<=("124"_b, "123"_b));
        CHECK_LE("12"_b, "123"_b);
        CHECK_FALSE(operator<=("123"_b, "12"_b));
    }

    SUBCASE("greater") {
        CHECK_FALSE(operator>(b, b));
        CHECK_GT("124"_b, "123"_b);
        CHECK_FALSE(operator>("123"_b, "124"_b));
        CHECK_GT("123"_b, "12"_b);
        CHECK_FALSE(operator>("12"_b, "123"_b));
    }

    SUBCASE("grater equal") {
        CHECK_GE(b, b);
        CHECK_GE("124"_b, "123"_b);
        CHECK_FALSE(operator>=("123"_b, "124"_b));
        CHECK_GE("123"_b, "12"_b);
        CHECK_FALSE(operator>=("12"_b, "123"_b));
    }
}

TEST_CASE("find") {
    const auto b = "123"_b;
    const auto empty = ""_b;

    SUBCASE("single byte") {
        SUBCASE("default start") {
            CHECK_EQ(b.find('2'), b.at(1));
            CHECK_EQ(b.find('a'), b.end());
            CHECK_EQ(empty.find('a'), empty.end());
        }

        SUBCASE("start at target") {
            CHECK_EQ(b.find('2', b.at(1)), b.at(1));
            CHECK_EQ(b.find('a', b.at(1)), b.end());
        }

        SUBCASE("start beyond target") {
            CHECK_EQ(b.find('2', b.at(2)), b.end());
            CHECK_EQ(b.find('a', b.at(2)), b.end());
            CHECK_EQ(b.find('a', b.end()), b.end());
        }
    }

    SUBCASE("range of bytes") {
        SUBCASE("default start") {
            CHECK_EQ(b.find("23"_b), std::make_tuple(true, b.at(1)));
            CHECK_EQ(b.find("234"_b), std::make_tuple(false, b.at(1)));
            CHECK_EQ(b.find("22"_b), std::make_tuple(false, b.end()));
            CHECK_EQ(b.find("a"_b), std::make_tuple(false, b.end()));
            CHECK_EQ(b.find(""_b), std::make_tuple(true, b.begin()));
            CHECK_EQ(empty.find("a"_b), std::make_tuple(false, empty.end()));
            CHECK_EQ(empty.find(""_b), std::make_tuple(true, empty.begin()));
        }

        SUBCASE("start at target") {
            CHECK_EQ(b.find("23"_b, b.at(1)), std::make_tuple(true, b.at(1)));
            CHECK_EQ(b.find("ab"_b, b.at(1)), std::make_tuple(false, b.end()));
        }

        SUBCASE("start beyond target") {
            CHECK_EQ(b.find("23"_b, b.at(2)), std::make_tuple(false, b.end()));
            CHECK_EQ(b.find("ab"_b, b.at(2)), std::make_tuple(false, b.end()));
            CHECK_EQ(b.find("ab"_b, b.end()), std::make_tuple(false, b.end()));
        }
    }
}

TEST_CASE("join") {
    CHECK_EQ(""_b.join(Vector<int>({1, 2, 3})), "123"_b);
    CHECK_EQ("😎"_b.join(Vector<int>({1, 2, 3})), "1😎2😎3"_b);
    CHECK_EQ("😎"_b.join(Vector<Bytes>({"\x00"_b, "\x01"_b, "\x02"_b})), "\\x00😎\\x01😎\\x02"_b);
}

TEST_CASE("lower") {
    CHECK_EQ("ABC123"_b.lower(unicode::Charset::UTF8).str(), "abc123");
    CHECK_EQ("ABC123"_b.lower(unicode::Charset::ASCII).str(), "abc123");
    CHECK_EQ("Gänsefüßchen"_b.lower(unicode::Charset::UTF8).str(), "gänsefüßchen");
    CHECK_EQ("Gänsefüßchen"_b.lower(unicode::Charset::ASCII).str(), "g??nsef????chen");

    // NOLINTNEXTLINE(bugprone-throw-keyword-missing)
    CHECK_THROWS_WITH_AS("123"_b.lower(unicode::Charset::Undef), "unknown character set for decoding",
                         const RuntimeError&);

    // No case change expected for these Japanese codepoints.
    const auto tokio8 = "東京"_b;
    CHECK_EQ(tokio8.lower(unicode::Charset::UTF16LE, unicode::DecodeErrorStrategy::STRICT), tokio8);

    const auto tokio16 = "\xff\xfeqg\xacN"_b; // 東京 in UTF16LE.
    CHECK_EQ(tokio16.lower(unicode::Charset::UTF16LE, unicode::DecodeErrorStrategy::STRICT), tokio16);
}

TEST_CASE("match") {
    const auto b = "123"_b;
    CHECK_EQ(b.match(RegExp({".*2"}), 0), Result("12"_b));
    CHECK_EQ(b.match(RegExp({".*(2)"}), 1), Result("2"_b));
    CHECK_EQ(b.match(RegExp({".*a"}), 0), Result<Bytes>(result::Error("no matches found")));
    CHECK_EQ(b.match(RegExp({".*2"}), 1), Result<Bytes>(result::Error("no matches found")));
}

TEST_CASE("iteration") {
    // Validate that when iterating we yield the `Iterator`'s `reference` type.
    // This is a regression test for #219.
    for ( auto x : Bytes() ) {
        (void)x;
        static_assert(std::is_same_v<decltype(x), integer::safe<uint8_t>>);
    }
}

TEST_CASE("unsafe iteration") {
    const auto b = "123"_b;
    auto i = b.unsafeBegin();
    CHECK_EQ(*i, '1');
    CHECK_EQ(*(++i), '2');
    CHECK_EQ(*(++i), '3');
    CHECK_EQ(++i, b.unsafeEnd());

    // Check yield type, like above.
    for ( auto i = b.unsafeBegin(); i != b.unsafeEnd(); ++i ) {
        (void)i;
        static_assert(std::is_same_v<decltype(*i), uint8_t>);
    }
}

TEST_CASE("split") {
    SUBCASE("separator") {
        CHECK_EQ("12 45"_b.split(" "), Vector({"12"_b, "45"_b}));
        CHECK_EQ("12 45 678"_b.split(" "), Vector({"12"_b, "45"_b, "678"_b}));
        CHECK_EQ("12345"_b.split("34"), Vector({"12"_b, "5"_b}));
        CHECK_EQ(" 2345"_b.split(" "), Vector({""_b, "2345"_b}));
        CHECK_EQ("12345"_b.split(""), Vector({"12345"_b}));
        CHECK_EQ("12345"_b.split("6"), Vector({"12345"_b}));
        CHECK_EQ("12 34 5"_b.split(""), Vector({"12 34 5"_b}));
        CHECK_EQ(" "_b.split(" "), Vector({""_b, ""_b}));
        CHECK_EQ(""_b.split(" "), Vector({""_b}));
        CHECK_EQ(""_b.split(""), Vector({""_b}));
    }

    SUBCASE("whitespace") {
        CHECK_EQ("12 45"_b.split(), Vector({"12"_b, "45"_b}));
        CHECK_EQ("12 45 678"_b.split(), Vector({"12"_b, "45"_b, "678"_b}));

        // TODO(bbannier): This should be symmetric with `split(" ")`.
        CHECK_EQ(" 2345"_b.split(), Vector({"2345"_b}));

        // TODO(bbannier): This should be symmetric with `split(" ")`.
        CHECK_EQ(" "_b.split(), Vector<Bytes>());

        // TODO(bbannier): This should be symmetric with `split(" ")`.
        CHECK_EQ(""_b.split(), Vector<Bytes>());

        CHECK_EQ("1"_b.split(), Vector({"1"_b}));
    }
}

TEST_CASE("split1") {
    SUBCASE("separator") {
        CHECK_EQ("12 45"_b.split1(" "), std::make_tuple("12"_b, "45"_b));
        CHECK_EQ("12 45 678"_b.split1(" "), std::make_tuple("12"_b, "45 678"_b));
        CHECK_EQ("12345"_b.split1("34"), std::make_tuple("12"_b, "5"_b));
        CHECK_EQ(" 2345"_b.split1(" "), std::make_tuple(""_b, "2345"_b));
        CHECK_EQ("12345"_b.split1(""), std::make_tuple(""_b, "12345"_b));
        CHECK_EQ("12345"_b.split1("6"), std::make_tuple("12345"_b, ""_b));
        CHECK_EQ("12 34 5"_b.split1(""), std::make_tuple(""_b, "12 34 5"_b));
        CHECK_EQ("1"_b.split1(" "), std::make_tuple("1"_b, ""_b));
        CHECK_EQ(""_b.split1("1"), std::make_tuple(""_b, ""_b));
        CHECK_EQ(""_b.split1(""), std::make_tuple(""_b, ""_b));
    }

    SUBCASE("whitespace") {
        CHECK_EQ("12 45"_b.split1(), std::make_tuple("12"_b, "45"_b));
        CHECK_EQ("12 45 678"_b.split1(), std::make_tuple("12"_b, "45 678"_b));

        // TODO(bbannier): This should be symmetric with `split(" ")`.
        CHECK_EQ(" 2345"_b.split1(), std::make_tuple(""_b, "2345"_b));

        CHECK_EQ(" "_b.split1(), std::make_tuple(""_b, ""_b));
        CHECK_EQ(""_b.split1(), std::make_tuple(""_b, ""_b));
        CHECK_EQ("1"_b.split1(), std::make_tuple("1"_b, ""_b));
    }
}

TEST_CASE("startsWith") {
    CHECK("123"_b.startsWith(""_b));
    CHECK("123"_b.startsWith("1"_b));
    CHECK("123"_b.startsWith("12"_b));
    CHECK("123"_b.startsWith("123"_b));

    CHECK_FALSE("123"_b.startsWith("1234"_b));
    CHECK_FALSE("123"_b.startsWith("a"_b));
    CHECK_FALSE(""_b.startsWith("a"_b));
}

TEST_CASE("endsWith") {
    CHECK("123"_b.endsWith(""_b));
    CHECK("123"_b.endsWith("3"_b));
    CHECK("123"_b.endsWith("23"_b));
    CHECK("123"_b.endsWith("123"_b));

    CHECK_FALSE("123"_b.endsWith("1234"_b));
    CHECK_FALSE("123"_b.endsWith("a"_b));
    CHECK_FALSE(""_b.endsWith("a"_b));
}

TEST_CASE("strip") {
    SUBCASE("whitespace") {
        CHECK_EQ("\t 123 "_b.strip(bytes::Side::Left), "123 "_b);
        CHECK_EQ(" 123 \v"_b.strip(bytes::Side::Right), " 123"_b);
        CHECK_EQ("\r\f 123 \n"_b.strip(bytes::Side::Both), "123"_b);
    }

    SUBCASE("bytes") {
        CHECK_EQ("\t 123 "_b.strip("\t\r "_b, bytes::Side::Left), "123 "_b);
        CHECK_EQ(" 123 \v"_b.strip(" \v"_b, bytes::Side::Right), " 123"_b);
        CHECK_EQ("\r\f 123 \n"_b.strip("\n \f\r"_b, bytes::Side::Both), "123"_b);
    }
}

TEST_CASE("sub") {
    const auto b = "123456"_b;

    SUBCASE("end offset") {
        CHECK_EQ(b.sub(0), ""_b);
        CHECK_EQ(b.sub(b.size()), b);
        CHECK_EQ(b.sub(b.size() + 1024), b);
        CHECK_EQ(b.sub(99), b);
        CHECK_EQ(b.sub(3), "123"_b);
    }

    SUBCASE("start/end offsets") {
        CHECK_EQ(b.sub(0, 0), ""_b);
        CHECK_EQ(b.sub(b.size(), b.size()), ""_b);
        CHECK_EQ(b.sub(0, b.size()), b);
        CHECK_EQ(b.sub(0, 3), "123"_b);
        CHECK_EQ(b.sub(3, 0), "456"_b);

        CHECK_THROWS_WITH_AS(b.sub(b.size() + 1024, b.size() + 2048),
                             "start index 1030 out of range for bytes with length 6", const OutOfRange);
    }

    SUBCASE("end iterator") {
        CHECK_EQ(b.sub(b.begin()), ""_b);
        CHECK_EQ(b.sub(b.end()), b);
        CHECK_EQ(b.sub(++b.end()), b);

        const auto bb = "123"_b;
        CHECK_THROWS_WITH_AS(b.sub(bb.begin()), "start and end iterator cannot belong to different bytes",
                             const InvalidArgument&);
    }

    SUBCASE("start/end iterator") {
        CHECK_EQ(b.sub(b.begin(), b.end()), b);
        CHECK_EQ(b.sub(b.begin(), b.begin()), ""_b);
        CHECK_EQ(b.sub(b.end(), b.begin()), ""_b);
        CHECK_THROWS_WITH_AS(b.sub(++b.end(), ++b.begin()), "start index 7 out of range for bytes with length 6",
                             const OutOfRange&);
        CHECK_THROWS_WITH_AS(b.sub(++b.end(), ++b.end()), "start index 7 out of range for bytes with length 6",
                             const OutOfRange&);

        const auto bb = "123"_b;
        // NOLINTNEXTLINE(bugprone-throw-keyword-missing)
        CHECK_THROWS_WITH_AS(b.sub(b.begin(), bb.begin()), "start and end iterator cannot belong to different bytes",
                             const InvalidArgument&);
    }
}

TEST_CASE("toInt") {
    SUBCASE("with base") {
        CHECK_EQ("100"_b.toInt(), 100);
        CHECK_EQ("100"_b.toInt(2), 4);
        CHECK_EQ("-100"_b.toInt(2), -4);

        CHECK_THROWS_WITH_AS(""_b.toInt(16), "cannot decode from empty range", const RuntimeError&);
        CHECK_THROWS_WITH_AS("12a"_b.toInt(), "cannot parse bytes as signed integer", const RuntimeError&);
    }

    SUBCASE("with byte order") {
        CHECK_EQ("100"_b.toInt(Enum(ByteOrder::Big)), 3223600);
        CHECK_EQ("100"_b.toInt(Enum(ByteOrder::Network)), 3223600);
        CHECK_EQ("100"_b.toInt(Enum(ByteOrder::Little)), 3158065);

        CHECK_EQ("\x00\x00\x00\x01\x01"_b.toInt(Enum(ByteOrder::Big)), 257);
        CHECK_EQ("\xff"_b.toInt(Enum(ByteOrder::Big)), -1);
        CHECK_EQ("\xff\xff"_b.toInt(Enum(ByteOrder::Big)), -1);
        CHECK_EQ("\xff\xff\xff\xff"_b.toInt(Enum(ByteOrder::Big)), -1);
        CHECK_EQ("\xff\xff\xff\xff\xff\xff"_b.toInt(Enum(ByteOrder::Big)), -1);
        CHECK_EQ("\xff\xff\xff\xff\xff\xff\xff\xff"_b.toInt(Enum(ByteOrder::Big)), -1);

        // 2er complement according to Wikipedia: -(2**39) + 2**8 + 2**0 = -549755813631
        CHECK_EQ("\x80\x00\x00\x01\x01"_b.toInt(Enum(ByteOrder::Big)), -549755813631);
        CHECK_EQ("\x01\x01\x00\x00\x80"_b.toInt(Enum(ByteOrder::Little)), -549755813631);

        if ( systemByteOrder().value() == ByteOrder::Little )
            CHECK_EQ("100"_b.toInt(Enum(ByteOrder::Host)), 3158065);
        else
            CHECK_EQ("100"_b.toInt(ByteOrder::Big), 3223600);

        CHECK_THROWS_WITH_AS(""_b.toInt(Enum(ByteOrder::Big)), "not enough bytes for conversion to integer",
                             const InvalidValue&);

        CHECK_THROWS_WITH_AS("1234567890"_b.toInt(Enum(ByteOrder::Big)),
                             "more than max of 8 bytes for conversion to integer (have 10)", const InvalidValue&);

        CHECK_THROWS_WITH_AS("100"_b.toInt(Enum(ByteOrder::Undef)), "cannot convert value to undefined byte order",
                             const InvalidArgument&);
    }
}

TEST_CASE("toUInt") {
    SUBCASE("with base") {
        CHECK_EQ("100"_b.toUInt(), 100U);
        CHECK_EQ("100"_b.toUInt(2), 4U);
        CHECK_THROWS_WITH_AS("-100"_b.toUInt(2), "integer overflow", const RuntimeError&);

        CHECK_THROWS_WITH_AS("12a"_b.toUInt(), "cannot parse bytes as unsigned integer", const RuntimeError&);
    }

    SUBCASE("with byte order") {
        CHECK_EQ("100"_b.toUInt(Enum(ByteOrder::Big)), 3223600U);
        CHECK_EQ("100"_b.toUInt(Enum(ByteOrder::Network)), 3223600U);
        CHECK_EQ("100"_b.toUInt(Enum(ByteOrder::Little)), 3158065U);
        CHECK_EQ("100"_b.toUInt(Enum(ByteOrder::Host)), 3158065U);

        CHECK_THROWS_WITH_AS(""_b.toUInt(Enum(ByteOrder::Big)), "not enough bytes for conversion to integer",
                             const InvalidValue&);

        CHECK_THROWS_WITH_AS("1234567890"_b.toUInt(Enum(ByteOrder::Big)),
                             "more than max of 8 bytes for conversion to integer (have 10)", const InvalidValue&);

        CHECK_THROWS_WITH_AS("100"_b.toInt(Enum(ByteOrder::Undef)), "cannot convert value to undefined byte order",
                             const InvalidArgument&);
    }
}

TEST_CASE("toReal") {
    CHECK_EQ("100"_b.toReal(), 100);
    CHECK_EQ("0."_b.toReal(), 0.);

    CHECK_EQ("0.5"_b.toReal(), 0.5);
    CHECK_EQ("-0.5"_b.toReal(), -0.5);
    CHECK_EQ("+0.5"_b.toReal(), +0.5);
    CHECK_EQ(".5"_b.toReal(), 0.5);
    CHECK_EQ("-.5"_b.toReal(), -0.5);

    CHECK_EQ("1e42"_b.toReal(), 1e42);
    CHECK_EQ("+1e42"_b.toReal(), 1e42);
    CHECK_EQ("-1e42"_b.toReal(), -1e42);

    CHECK_EQ("1e+42"_b.toReal(), 1e42);
    CHECK_EQ("1e-42"_b.toReal(), 1e-42);

    CHECK_EQ("inf"_b.toReal(), std::numeric_limits<double>::infinity());
    CHECK_EQ("-inf"_b.toReal(), -std::numeric_limits<double>::infinity());

    CHECK(std::isnan("nan"_b.toReal()));
    CHECK(std::isnan("-nan"_b.toReal()));

    CHECK_THROWS_WITH_AS(""_b.toReal(), "cannot parse real value: ''", const InvalidValue&);
    CHECK_THROWS_WITH_AS("abc"_b.toReal(), "cannot parse real value: 'abc'", const InvalidValue&);
    CHECK_THROWS_WITH_AS("a.2"_b.toReal(), "cannot parse real value: 'a.2'", const InvalidValue&);
    CHECK_THROWS_WITH_AS("2.a"_b.toReal(), "cannot parse real value: '2.a'", const InvalidValue&);

    // The next test should fail independent of the locale, so let's set one.

    auto* de_locale = newlocale(LC_ALL_MASK, "de_DE.UTF-8", nullptr);
    if ( ! de_locale )
        FAIL("failed to create de_DE locale; locales not installed?");

    auto* old_locale = uselocale(de_locale);
    CHECK_THROWS_WITH_AS("1,0"_b.toReal(), "cannot parse real value: '1,0'", const InvalidValue&);
    uselocale(old_locale);

    freelocale(de_locale);
}

TEST_CASE("toTime") {
    CHECK_EQ("10"_b.toTime(), Time(10, Time::SecondTag()));
    CHECK_EQ("10"_b.toTime(2), Time(2, Time::SecondTag()));

    CHECK_EQ(""_b.toTime(), Time());
    CHECK_THROWS_WITH_AS("abc"_b.toTime(), "cannot parse bytes as unsigned integer", const RuntimeError&);

    CHECK_EQ("\x00\x01"_b.toTime(Enum(ByteOrder::Big)), Time(1, Time::SecondTag()));
    CHECK_EQ("\x01\x00"_b.toTime(Enum(ByteOrder::Little)), Time(1, Time::SecondTag()));

    CHECK_EQ("\x04\x4B\x80\x00\x00"_b.toTime(Enum(ByteOrder::Big)),
             Time(18446548992, Time::SecondTag())); // Value near end of `Time` range.
    CHECK_THROWS_WITH_AS("\x04\x4B\x90\x00\x00"_b.toTime(Enum(ByteOrder::Big)), "integer overflow",
                         const RuntimeError&); // Value beyond end of `Time` range.
}

TEST_CASE("upper") {
    CHECK_EQ("abc123"_b.upper(unicode::Charset::UTF8).str(), "ABC123");
    CHECK_EQ("abc123"_b.upper(unicode::Charset::ASCII).str(), "ABC123");
    CHECK_EQ("Gänsefüßchen"_b.upper(unicode::Charset::UTF8).str(), "GÄNSEFÜẞCHEN");
    CHECK_EQ("Gänsefüßchen"_b.upper(unicode::Charset::ASCII).str(), "G??NSEF????CHEN");

    CHECK_EQ(Bytes("a\0b\0c\0"s).upper(unicode::Charset::UTF16LE, unicode::DecodeErrorStrategy::STRICT),
             Bytes("A\0B\0C\0"s).upper(unicode::Charset::UTF16LE, unicode::DecodeErrorStrategy::STRICT));

    // NOLINTNEXTLINE(bugprone-throw-keyword-missing)
    CHECK_THROWS_WITH_AS("123"_b.upper(unicode::Charset::Undef), "unknown character set for decoding",
                         const RuntimeError&);

    // No case change expected for these Japanese codepoints.
    const auto tokio8 = "東京"_b;
    CHECK_EQ(tokio8.upper(unicode::Charset::UTF16LE, unicode::DecodeErrorStrategy::STRICT), tokio8);

    const auto tokio16 = "\xff\xfeqg\xacN"_b; // 東京 in UTF16LE.
    CHECK_EQ(tokio16.upper(unicode::Charset::UTF16LE, unicode::DecodeErrorStrategy::STRICT), tokio16);
}

TEST_CASE("append") {
    auto b = "123"_b;
    auto it = b.begin();

    REQUIRE_EQ(to_string(b), "b\"123\"");
    REQUIRE_EQ(*it, '1');

    SUBCASE("Bytes") {
        b.append("456"_b);

        CHECK_EQ(to_string(b), "b\"123456\"");
        CHECK_EQ(*it, '1');
    }

    SUBCASE("View") {
        auto stream = Stream("456");
        b.append(stream.view());

        CHECK_EQ(to_string(b), "b\"123456\"");
        CHECK_EQ(*it, '1');
    }

    SUBCASE("Byte") {
        b.append('4');
        b.append('5');
        b.append('6');

        CHECK_EQ(to_string(b), "b\"123456\"");
        CHECK_EQ(*it, '1');
    }
}

TEST_CASE("assign") {
    auto b = "123"_b;
    auto it = b.begin();

    REQUIRE_EQ(to_string(b), "b\"123\"");
    REQUIRE_EQ(*it, '1');

    SUBCASE("rvalue") {
        b = "abc"_b;
        CHECK_EQ(to_string(b), "b\"abc\"");
        CHECK_THROWS_WITH_AS(*it, "underlying object has expired", const InvalidIterator&);
    }

    SUBCASE("lvalue") {
        const auto bb = "abc"_b;
        b = bb;
        CHECK_EQ(to_string(b), "b\"abc\"");
        CHECK_THROWS_WITH_AS(*it, "underlying object has expired", const InvalidIterator&);
    }
}

TEST_CASE("Iterator") {
    const auto b = "123"_b;
    const auto bb = "123"_b;

    SUBCASE("coupled lifetime") {
        CHECK_NOTHROW(*b.begin()); // Iterator valid since container is alife.

        auto it = ""_b.begin();
        CHECK_THROWS_WITH_AS(*it, "underlying object has expired", const InvalidIterator&);
    }

    SUBCASE("increment") {
        auto it = b.begin();
        CHECK_EQ(*(it++), '1');
        CHECK_EQ(*it, '2');
        CHECK_EQ(*(++it), '3');
        it += 1;
        CHECK_EQ(it, b.end());

        CHECK_EQ(*(b.begin() + 2), '3');
        CHECK_EQ(*(b.begin() + integer::safe<uint8_t>(2)), '3');

        it = b.begin();
        it += integer::safe<uint64_t>(2);
        CHECK_EQ(*it, '3');
    }

    SUBCASE("bounds check") {
        CHECK_EQ(*b.begin(), '1');
        CHECK_THROWS_WITH_AS(*b.end(), "index 3 out of bounds", const IndexError&);
    }

    SUBCASE("equality") {
        CHECK_EQ(b.begin(), b.begin());
        CHECK_NE(b.begin(), b.end());

        CHECK_THROWS_WITH_AS(operator==(b.begin(), bb.begin()), "cannot compare iterators into different bytes",
                             const InvalidArgument&);
    }

    SUBCASE("distance") {
        CHECK_EQ(b.end() - b.begin(), b.size());
        CHECK_THROWS_WITH_AS(b.begin() - b.end(), "integer overflow", const RuntimeError&);
        CHECK_EQ(b.end() - b.end(), 0);
        CHECK_EQ(b.begin() - b.begin(), 0);

        CHECK_THROWS_WITH_AS(operator-(b.begin(), bb.begin()),
                             "cannot perform arithmetic with iterators into different bytes", const InvalidArgument&);
    }

    SUBCASE("ordering") {
        SUBCASE("less") {
            REQUIRE_FALSE(b.isEmpty());

            CHECK_LT(b.begin(), b.end());
            CHECK_FALSE(operator<(b.end(), b.begin()));
            CHECK_THROWS_WITH_AS(operator<(b.begin(), bb.begin()), "cannot compare iterators into different bytes",
                                 const InvalidArgument&);
        }

        SUBCASE("less equal") {
            REQUIRE_FALSE(b.isEmpty());

            CHECK_LE(b.begin(), b.end());
            CHECK_LE(b.begin(), b.begin());
            CHECK_FALSE(operator<=(b.end(), b.begin()));
            CHECK_THROWS_WITH_AS(operator<=(b.begin(), bb.begin()), "cannot compare iterators into different bytes",
                                 const InvalidArgument&);
        }

        SUBCASE("greater") {
            REQUIRE_FALSE(b.isEmpty());

            CHECK_GT(b.end(), b.begin());
            CHECK_FALSE(operator>(b.begin(), b.end()));
            CHECK_THROWS_WITH_AS(operator>(b.begin(), bb.begin()), "cannot compare iterators into different bytes",
                                 const InvalidArgument&);
        }

        SUBCASE("greater equal") {
            REQUIRE_FALSE(b.isEmpty());

            CHECK_GE(b.end(), b.begin());
            CHECK_GE(b.begin(), b.begin());
            CHECK_FALSE(operator>=(b.begin(), b.end()));
            CHECK_THROWS_WITH_AS(operator>=(b.begin(), bb.begin()), "cannot compare iterators into different bytes",
                                 const InvalidArgument&);
        }
    }
}

TEST_CASE("issue 599") {
    // This is a regression test for #599.
    std::optional<Bytes> a;
    a = "31"_b;
    REQUIRE(a);
    CHECK_EQ(*a, "31"_b);
    CHECK_EQ(a->toInt(), 31);
}

TEST_CASE("to_string") {
    CHECK_EQ(to_string("abc"_b), "b\"abc\"");
    CHECK_EQ(to_string("\"\\"_b), "b\"\\\"\\\\\"");
}

TEST_CASE("to_string_for_print") {
    CHECK_EQ(to_string_for_print("abc"_b), "abc");
    CHECK_EQ(to_string_for_print("\\\""_b), "\\\"");
}
TEST_SUITE_END();
