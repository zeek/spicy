// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <hilti/rt/types/bytes.h>
#include <hilti/rt/types/string.h>
#include <hilti/rt/types/vector.h>
#include <hilti/rt/unicode.h>

using namespace hilti::rt;
using namespace hilti::rt::bytes::literals;
using namespace hilti::rt::string::literals;

TEST_SUITE_BEGIN("string");

TEST_CASE("encode") {
    CHECK_EQ(string::encode(""_hs, unicode::Charset::ASCII), ""_b);
    CHECK_EQ(string::encode("123"_hs, unicode::Charset::ASCII), "123"_b);
    CHECK_EQ(string::encode("abc"_hs, unicode::Charset::ASCII), "abc"_b);
    CHECK_EQ(string::encode("abc"_hs, unicode::Charset::UTF8), "abc"_b);

    CHECK_EQ(string::encode("\xF0\x9F\x98\x85"_hs, unicode::Charset::UTF8), "\xF0\x9F\x98\x85"_b);
    CHECK_EQ(string::encode("\xc3\x28"_hs, unicode::Charset::UTF8), "\ufffd("_b);
    CHECK_EQ(string::encode("\xc3\x28"_hs, unicode::Charset::UTF8, unicode::DecodeErrorStrategy::IGNORE), "("_b);
    CHECK_THROWS_WITH_AS(string::encode("\xc3\x28"_hs, unicode::Charset::UTF8, unicode::DecodeErrorStrategy::STRICT),
                         "illegal UTF8 sequence in string", const RuntimeError&);


    CHECK_EQ(string::encode("\xF0\x9F\x98\x85"_hs, unicode::Charset::ASCII, unicode::DecodeErrorStrategy::REPLACE),
             "????"_b);
    CHECK_EQ(string::encode("\xF0\x9F\x98\x85"_hs, unicode::Charset::ASCII, unicode::DecodeErrorStrategy::IGNORE),
             ""_b);
    CHECK_THROWS_WITH_AS(string::encode("\xF0\x9F\x98\x85"_hs, unicode::Charset::ASCII,
                                        unicode::DecodeErrorStrategy::STRICT),
                         "illegal ASCII character in string", const RuntimeError&);

    CHECK_EQ(string::encode("abc"_hs, unicode::Charset::UTF16LE, unicode::DecodeErrorStrategy::STRICT), "a\0b\0c\0"_b);
    CHECK_EQ(string::encode("abc"_hs, unicode::Charset::UTF16BE, unicode::DecodeErrorStrategy::STRICT), "\0a\0b\0c"_b);
    CHECK_EQ(string::encode("東京"_hs, unicode::Charset::UTF16LE, unicode::DecodeErrorStrategy::STRICT), "qg\xacN"_b);
    CHECK_EQ(string::encode("東京"_hs, unicode::Charset::UTF16BE, unicode::DecodeErrorStrategy::STRICT), "gqN\xac"_b);

    // NOLINTNEXTLINE(bugprone-throw-keyword-missing)
    CHECK_THROWS_WITH_AS(string::encode("123"_hs, unicode::Charset::Undef), "unknown character set for encoding",
                         const RuntimeError&);
}

TEST_CASE("lower") {
    CHECK_EQ(string::lower(""_hs), ""_hs);
    CHECK_EQ(string::lower("123Abc"_hs), "123abc"_hs);
    CHECK_EQ(string::lower("GÄNSEFÜẞCHEN"_hs), "gänsefüßchen"_hs);
    CHECK_EQ(string::lower("\xc3\x28"
                           "aBcD"_hs,
                           unicode::DecodeErrorStrategy::REPLACE),
             "\ufffd(abcd"_hs);
    CHECK_EQ(string::lower("\xc3\x28"
                           "aBcD"_hs,
                           unicode::DecodeErrorStrategy::IGNORE),
             "(abcd"_hs);
    CHECK_THROWS_WITH_AS(string::lower("\xc3\x28"
                                       "aBcD"_hs,
                                       unicode::DecodeErrorStrategy::STRICT),
                         "illegal UTF8 sequence in string", const RuntimeError&);
}

TEST_CASE("size") {
    CHECK_EQ(string::size(""_hs), 0U);
    CHECK_EQ(string::size("123Abc"_hs), 6U);
    CHECK_EQ(string::size("Gänsefüßchen"_hs), 12U);
    CHECK_EQ(string::size("\xc3\x28"
                          "aBcD"_hs,
                          unicode::DecodeErrorStrategy::REPLACE),
             6U);
    CHECK_EQ(string::size("\xc3\x28"
                          "aBcD"_hs,
                          unicode::DecodeErrorStrategy::IGNORE),
             5U);
    CHECK_THROWS_WITH_AS(string::size("\xc3\x28"
                                      "aBcD"_hs,
                                      unicode::DecodeErrorStrategy::STRICT),
                         "illegal UTF8 sequence in string", const RuntimeError&);
}

TEST_CASE("upper") {
    CHECK_EQ(string::upper(""_hs), ""_hs);
    CHECK_EQ(string::upper("123Abc"_hs), "123ABC"_hs);
    CHECK_EQ(string::upper("Gänsefüßchen"_hs), "GÄNSEFÜẞCHEN"_hs);
    CHECK_EQ(string::upper("\xc3\x28"
                           "aBcD"_hs,
                           unicode::DecodeErrorStrategy::REPLACE),
             "\ufffd(ABCD"_hs);
    CHECK_EQ(string::upper("\xc3\x28"
                           "aBcD"_hs,
                           unicode::DecodeErrorStrategy::IGNORE),
             "(ABCD"_hs);
    CHECK_THROWS_WITH_AS(string::upper("\xc3\x28"
                                       "aBcD"_hs,
                                       unicode::DecodeErrorStrategy::STRICT),
                         "illegal UTF8 sequence in string", const RuntimeError&);
}

TEST_CASE("to_string") {
    CHECK_EQ(to_string("abc"_hs), "\"abc\"");
    CHECK_EQ(to_string(std::string_view("abc")), "\"abc\"");
    CHECK_EQ(to_string("\"\\"_hs), "\"\\\"\\\\\"");
}

TEST_CASE("to_string_for_print") {
    CHECK_EQ(to_string_for_print("abc"_hs), "abc");
    CHECK_EQ(to_string_for_print(std::string_view("abc")), "abc");
    CHECK_EQ(to_string_for_print("\\\""_hs), "\\\"");
    CHECK_EQ(to_string_for_print(std::string_view("\\\"")), "\\\"");
}

TEST_CASE("split") {
    SUBCASE("separator") {
        CHECK_EQ(string::split("12 45"_hs, " "_hs), Vector<String>({"12"_hs, "45"_hs}));
        CHECK_EQ(string::split("12 45 678"_hs, " "_hs), Vector<String>({"12"_hs, "45"_hs, "678"_hs}));
        CHECK_EQ(string::split("12345"_hs, "34"_hs), Vector<String>({"12"_hs, "5"_hs}));
        CHECK_EQ(string::split(" 2345"_hs, " "_hs), Vector<String>({""_hs, "2345"_hs}));
        CHECK_EQ(string::split("12345"_hs, ""_hs), Vector<String>({"12345"_hs}));
        CHECK_EQ(string::split("12345"_hs, "6"_hs), Vector<String>({"12345"_hs}));
        CHECK_EQ(string::split("12 34 5"_hs, ""_hs), Vector<String>({"12 34 5"_hs}));
        CHECK_EQ(string::split(" "_hs, " "_hs), Vector<String>({""_hs, ""_hs}));
        CHECK_EQ(string::split(""_hs, " "_hs), Vector<String>({""_hs}));
        CHECK_EQ(string::split(""_hs, ""_hs), Vector<String>({""_hs}));
    }

    SUBCASE("whitespace") {
        CHECK_EQ(string::split("12 45"_hs), Vector<String>({"12"_hs, "45"_hs}));
        CHECK_EQ(string::split("12 45 678"_hs), Vector<String>({"12"_hs, "45"_hs, "678"_hs}));
        CHECK_EQ(string::split("1"_hs), Vector<String>({"1"_hs}));

        // TODO: These (and the bytes tests) should match behavior with a provided separator
        CHECK_EQ(string::split(" 2345"_hs), Vector<String>({"2345"_hs}));
        CHECK_EQ(string::split(" "_hs), Vector<String>());
        CHECK_EQ(string::split(""_hs), Vector<String>());
    }

    SUBCASE("multibyte") {
        CHECK_EQ(string::split("𝔘𝔫𝔦𝔠𝔬𝔡𝔢"_hs, "𝔦"_hs), Vector<String>({"𝔘𝔫"_hs, "𝔠𝔬𝔡𝔢"_hs}));
        CHECK_EQ(string::split("𝔘𝔫𝔦𝔠𝔬𝔡𝔢"_hs, "i"_hs), Vector<String>({"𝔘𝔫𝔦𝔠𝔬𝔡𝔢"_hs}));
        CHECK_EQ(string::split("𝔘𝔫𝔦 𝔠𝔬𝔡𝔢"_hs), Vector<String>({"𝔘𝔫𝔦"_hs, "𝔠𝔬𝔡𝔢"_hs}));
    }
}

TEST_CASE("split1") {
    SUBCASE("separator") {
        CHECK_EQ(string::split1("12 45"_hs, " "_hs), tuple::make("12"_hs, "45"_hs));
        CHECK_EQ(string::split1("12 45 678"_hs, " "_hs), tuple::make("12"_hs, "45 678"_hs));
        CHECK_EQ(string::split1("12345"_hs, "34"_hs), tuple::make("12"_hs, "5"_hs));
        CHECK_EQ(string::split1(" 2345"_hs, " "_hs), tuple::make(""_hs, "2345"_hs));
        CHECK_EQ(string::split1("12345"_hs, ""_hs), tuple::make(""_hs, "12345"_hs));
        CHECK_EQ(string::split1("12345"_hs, "6"_hs), tuple::make("12345"_hs, ""_hs));
        CHECK_EQ(string::split1("12 34 5"_hs, ""_hs), tuple::make(""_hs, "12 34 5"_hs));
        CHECK_EQ(string::split1("1"_hs, " "_hs), tuple::make("1"_hs, ""_hs));
        CHECK_EQ(string::split1(""_hs, "1"_hs), tuple::make(""_hs, ""_hs));
        CHECK_EQ(string::split1(""_hs, ""_hs), tuple::make(""_hs, ""_hs));
    }

    SUBCASE("whitespace") {
        CHECK_EQ(string::split1("12 45"_hs), tuple::make("12"_hs, "45"_hs));
        CHECK_EQ(string::split1("12 45 678"_hs), tuple::make("12"_hs, "45 678"_hs));
        CHECK_EQ(string::split1(" 2345"_hs), tuple::make(""_hs, "2345"_hs));
        CHECK_EQ(string::split1("12345"_hs), tuple::make("12345"_hs, ""_hs));
        CHECK_EQ(string::split1(" "_hs), tuple::make(""_hs, ""_hs));
        CHECK_EQ(string::split1(""_hs), tuple::make(""_hs, ""_hs));
        CHECK_EQ(string::split1("1"_hs), tuple::make("1"_hs, ""_hs));
    }
}

TEST_SUITE_END();
