// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <ostream>
#include <tuple>
#include <type_traits>

#include <hilti/rt/doctest.h>
#include <hilti/rt/exception.h>
#include <hilti/rt/types/bytes.h>
#include <hilti/rt/types/integer.h>
#include <hilti/rt/types/regexp.h>

using namespace hilti::rt;
using namespace hilti::rt::bytes;

namespace std {
template<typename X, typename Y>
ostream& operator<<(ostream& stream, const tuple<X, Y>& xs) {
    return stream << '(' << hilti::rt::to_string(get<0>(xs)) << ", " << hilti::rt::to_string(get<1>(xs)) << ')';
}
} // namespace std

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

TEST_CASE("construct") {
    CHECK_EQ(Bytes("123", Enum(bytes::Charset::ASCII)).str(), "123");
    CHECK_EQ(Bytes("abc", Enum(bytes::Charset::ASCII)).str(), "abc");
    CHECK_EQ(Bytes("abc", Enum(bytes::Charset::UTF8)).str(), "abc");

    CHECK_EQ(Bytes("\xF0\x9F\x98\x85", Enum(bytes::Charset::UTF8)).str(), "\xF0\x9F\x98\x85");
    CHECK_EQ(Bytes("\xc3\x28", Enum(bytes::Charset::UTF8), bytes::DecodeErrorStrategy::REPLACE).str(), "\ufffd(");
    CHECK_EQ(Bytes("\xc3\x28", Enum(bytes::Charset::UTF8), bytes::DecodeErrorStrategy::IGNORE).str(), "(");
    CHECK_THROWS_WITH_AS(Bytes("\xc3\x28", Enum(bytes::Charset::UTF8), bytes::DecodeErrorStrategy::STRICT).str(),
                         "illegal UTF8 sequence in string", const RuntimeError&);

    CHECK_EQ(Bytes("\xF0\x9F\x98\x85", Enum(bytes::Charset::ASCII), bytes::DecodeErrorStrategy::REPLACE).str(), "????");
    CHECK_EQ(Bytes("\xF0\x9F\x98\x85", Enum(bytes::Charset::ASCII), bytes::DecodeErrorStrategy::IGNORE).str(), "");
    CHECK_THROWS_WITH_AS(Bytes("\xF0\x9F\x98\x85", Enum(bytes::Charset::ASCII), bytes::DecodeErrorStrategy::STRICT)
                             .str(),
                         "illegal ASCII character in string", const RuntimeError&);

    // NOLINTNEXTLINE(bugprone-throw-keyword-missing)
    CHECK_THROWS_WITH_AS(Bytes("123", Enum(bytes::Charset::Undef)), "unknown character set for encoding",
                         const RuntimeError&);
}

TEST_CASE("decode") {
    CHECK_EQ("123"_b.decode(bytes::Charset::ASCII), "123");
    CHECK_EQ("abc"_b.decode(bytes::Charset::ASCII), "abc");
    CHECK_EQ("abc"_b.decode(bytes::Charset::UTF8), "abc");
    CHECK_EQ("\xF0\x9F\x98\x85"_b.decode(bytes::Charset::UTF8), "\xF0\x9F\x98\x85");
    CHECK_EQ("\xF0\x9F\x98\x85"_b.decode(bytes::Charset::ASCII), "????");

    CHECK_EQ("€100"_b.decode(bytes::Charset::ASCII, bytes::DecodeErrorStrategy::REPLACE), "???100");
    CHECK_EQ("€100"_b.decode(bytes::Charset::ASCII, bytes::DecodeErrorStrategy::IGNORE), "100");
    CHECK_THROWS_WITH_AS("123ä4"_b.decode(bytes::Charset::ASCII, bytes::DecodeErrorStrategy::STRICT),
                         "illegal ASCII character in string", const RuntimeError&);

    CHECK_EQ("\xc3\x28"_b.decode(bytes::Charset::UTF8, bytes::DecodeErrorStrategy::REPLACE), "\ufffd(");
    CHECK_EQ("\xc3\x28"_b.decode(bytes::Charset::UTF8, bytes::DecodeErrorStrategy::IGNORE), "(");
    CHECK_THROWS_WITH_AS("\xc3\x28"_b.decode(bytes::Charset::UTF8, bytes::DecodeErrorStrategy::STRICT),
                         "illegal UTF8 sequence in string", const RuntimeError&);

    CHECK_THROWS_WITH_AS("123"_b.decode(bytes::Charset::Undef), "unknown character set for decoding",
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
    CHECK_EQ("ABC123"_b.lower(bytes::Charset::UTF8).str(), "abc123");
    CHECK_EQ("ABC123"_b.lower(bytes::Charset::ASCII).str(), "abc123");
    CHECK_EQ("Gänsefüßchen"_b.lower(bytes::Charset::UTF8).str(), "gänsefüßchen");
    CHECK_EQ("Gänsefüßchen"_b.lower(bytes::Charset::ASCII).str(), "g??nsef????chen");

    // NOLINTNEXTLINE(bugprone-throw-keyword-missing)
    CHECK_THROWS_WITH_AS("123"_b.lower(bytes::Charset::Undef), "unknown character set for decoding",
                         const RuntimeError&);
}

TEST_CASE("match") {
    const auto b = "123"_b;
    CHECK_EQ(b.match(RegExp(".*2"), 0), Result("12"_b));
    CHECK_EQ(b.match(RegExp(".*(2)"), 1), Result("2"_b));
    CHECK_EQ(b.match(RegExp(".*a"), 0), Result<Bytes>(result::Error("no matches found")));
    CHECK_EQ(b.match(RegExp(".*2"), 1), Result<Bytes>(result::Error("no matches found")));
}

TEST_CASE("iteration") {
    // Validate that when iterating we yield the `Iterator`'s `reference` type.
    // This is a regression test for #219.
    for ( auto x : Bytes() ) {
        (void)x;
        static_assert(std::is_same_v<decltype(x), uint8_t>);
    }
}

TEST_CASE("split") {
    SUBCASE("separator") {
        CHECK_EQ("12 45"_b.split(" "), Vector({"12"_b, "45"_b}));
        CHECK_EQ("12 45 678"_b.split(" "), Vector({"12"_b, "45"_b, "678"_b}));
        CHECK_EQ("12345"_b.split("34"), Vector({"12"_b, "5"_b}));
        CHECK_EQ(" 2345"_b.split(" "), Vector({""_b, "2345"_b}));
        CHECK_EQ("12345"_b.split(""), Vector({"12345"_b}));
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

        CHECK_THROWS_WITH_AS("12a"_b.toInt(), "cannot parse bytes as signed integer", const RuntimeError&);
    }

    SUBCASE("with byte order") {
        CHECK_EQ("100"_b.toInt(Enum(ByteOrder::Big)), 3223600);
        CHECK_EQ("100"_b.toInt(Enum(ByteOrder::Network)), 3223600);
        CHECK_EQ("100"_b.toInt(Enum(ByteOrder::Little)), 3158065);

        if ( systemByteOrder().value() == ByteOrder::Little )
            CHECK_EQ("100"_b.toInt(Enum(ByteOrder::Host)), 3158065);
        else
            CHECK_EQ("100"_b.toInt(ByteOrder::Big), 3223600);

        CHECK_THROWS_WITH_AS("1234567890"_b.toInt(Enum(ByteOrder::Big)),
                             "more than max of 8 bytes for conversion to integer", const RuntimeError&);

        CHECK_THROWS_WITH_AS("100"_b.toInt(Enum(ByteOrder::Undef)), "cannot convert value to undefined byte order",
                             const RuntimeError&);
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

        CHECK_THROWS_WITH_AS("1234567890"_b.toUInt(Enum(ByteOrder::Big)),
                             "more than max of 8 bytes for conversion to integer", const RuntimeError&);

        CHECK_THROWS_WITH_AS("100"_b.toInt(Enum(ByteOrder::Undef)), "cannot convert value to undefined byte order",
                             const RuntimeError&);
    }
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
    CHECK_EQ("abc123"_b.upper(bytes::Charset::UTF8).str(), "ABC123");
    CHECK_EQ("abc123"_b.upper(bytes::Charset::ASCII).str(), "ABC123");
    CHECK_EQ("Gänsefüßchen"_b.upper(bytes::Charset::UTF8).str(), "GÄNSEFÜẞCHEN");
    CHECK_EQ("Gänsefüßchen"_b.upper(bytes::Charset::ASCII).str(), "G??NSEF????CHEN");

    // NOLINTNEXTLINE(bugprone-throw-keyword-missing)
    CHECK_THROWS_WITH_AS("123"_b.upper(bytes::Charset::Undef), "unknown character set for decoding",
                         const RuntimeError&);
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
        CHECK_THROWS_WITH_AS(*it, "bound object has expired", const InvalidIterator&);
    }

    SUBCASE("lvalue") {
        const auto bb = "abc"_b;
        b = bb;
        CHECK_EQ(to_string(b), "b\"abc\"");
        CHECK_THROWS_WITH_AS(*it, "bound object has expired", const InvalidIterator&);
    }
}

TEST_CASE("Iterator") {
    const auto b = "123"_b;
    const auto bb = "123"_b;

    SUBCASE("coupled lifetime") {
        CHECK_NOTHROW(*b.begin()); // Iterator valid since container is alife.

        auto it = ""_b.begin();
        CHECK_THROWS_WITH_AS(*it, "bound object has expired", const InvalidIterator&);
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

TEST_SUITE_END();
