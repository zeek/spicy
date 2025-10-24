// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <hilti/rt/types/bytes.h>
#include <hilti/rt/types/string.h>
#include <hilti/rt/types/vector.h>
#include <hilti/rt/unicode.h>

using namespace std::string_literals;
using namespace hilti::rt;
using namespace hilti::rt::bytes::literals;

TEST_SUITE_BEGIN("string");

TEST_CASE("encode") {
    CHECK_EQ(string::encode("", unicode::Charset::ASCII), ""_b);
    CHECK_EQ(string::encode("123", unicode::Charset::ASCII), "123"_b);
    CHECK_EQ(string::encode("abc", unicode::Charset::ASCII), "abc"_b);
    CHECK_EQ(string::encode("abc", unicode::Charset::UTF8), "abc"_b);

    CHECK_EQ(string::encode("\xF0\x9F\x98\x85", unicode::Charset::UTF8), "\xF0\x9F\x98\x85"_b);
    CHECK_EQ(string::encode("\xc3\x28", unicode::Charset::UTF8), "\ufffd("_b);
    CHECK_EQ(string::encode("\xc3\x28", unicode::Charset::UTF8, unicode::DecodeErrorStrategy::IGNORE), "("_b);
    CHECK_THROWS_WITH_AS(string::encode("\xc3\x28", unicode::Charset::UTF8, unicode::DecodeErrorStrategy::STRICT),
                         "illegal UTF8 sequence in string", const RuntimeError&);


    CHECK_EQ(string::encode("\xF0\x9F\x98\x85", unicode::Charset::ASCII, unicode::DecodeErrorStrategy::REPLACE),
             "????"_b);
    CHECK_EQ(string::encode("\xF0\x9F\x98\x85", unicode::Charset::ASCII, unicode::DecodeErrorStrategy::IGNORE), ""_b);
    CHECK_THROWS_WITH_AS(string::encode("\xF0\x9F\x98\x85", unicode::Charset::ASCII,
                                        unicode::DecodeErrorStrategy::STRICT),
                         "illegal ASCII character in string", const RuntimeError&);

    CHECK_EQ(string::encode("abc", unicode::Charset::UTF16LE, unicode::DecodeErrorStrategy::STRICT), "a\0b\0c\0"_b);
    CHECK_EQ(string::encode("abc", unicode::Charset::UTF16BE, unicode::DecodeErrorStrategy::STRICT), "\0a\0b\0c"_b);
    CHECK_EQ(string::encode("東京", unicode::Charset::UTF16LE, unicode::DecodeErrorStrategy::STRICT), "qg\xacN"_b);
    CHECK_EQ(string::encode("東京", unicode::Charset::UTF16BE, unicode::DecodeErrorStrategy::STRICT), "gqN\xac"_b);

    // NOLINTNEXTLINE(bugprone-throw-keyword-missing)
    CHECK_THROWS_WITH_AS(string::encode("123", unicode::Charset::Undef), "unknown character set for encoding",
                         const RuntimeError&);
}

TEST_CASE("lower") {
    CHECK_EQ(string::lower(""), "");
    CHECK_EQ(string::lower("123Abc"), "123abc");
    CHECK_EQ(string::lower("GÄNSEFÜẞCHEN"), "gänsefüßchen");
    CHECK_EQ(string::lower("\xc3\x28"
                           "aBcD",
                           unicode::DecodeErrorStrategy::REPLACE),
             "\ufffd(abcd");
    CHECK_EQ(string::lower("\xc3\x28"
                           "aBcD",
                           unicode::DecodeErrorStrategy::IGNORE),
             "(abcd");
    CHECK_THROWS_WITH_AS(string::lower("\xc3\x28"
                                       "aBcD",
                                       unicode::DecodeErrorStrategy::STRICT),
                         "illegal UTF8 sequence in string", const RuntimeError&);
}

TEST_CASE("size") {
    CHECK_EQ(string::size(""), 0U);
    CHECK_EQ(string::size("123Abc"), 6U);
    CHECK_EQ(string::size("Gänsefüßchen"), 12U);
    CHECK_EQ(string::size("\xc3\x28"
                          "aBcD",
                          unicode::DecodeErrorStrategy::REPLACE),
             6U);
    CHECK_EQ(string::size("\xc3\x28"
                          "aBcD",
                          unicode::DecodeErrorStrategy::IGNORE),
             5U);
    CHECK_THROWS_WITH_AS(string::size("\xc3\x28"
                                      "aBcD",
                                      unicode::DecodeErrorStrategy::STRICT),
                         "illegal UTF8 sequence in string", const RuntimeError&);
}

TEST_CASE("upper") {
    CHECK_EQ(string::upper(""), "");
    CHECK_EQ(string::upper("123Abc"), "123ABC");
    CHECK_EQ(string::upper("Gänsefüßchen"), "GÄNSEFÜẞCHEN");
    CHECK_EQ(string::upper("\xc3\x28"
                           "aBcD",
                           unicode::DecodeErrorStrategy::REPLACE),
             "\ufffd(ABCD");
    CHECK_EQ(string::upper("\xc3\x28"
                           "aBcD",
                           unicode::DecodeErrorStrategy::IGNORE),
             "(ABCD");
    CHECK_THROWS_WITH_AS(string::upper("\xc3\x28"
                                       "aBcD",
                                       unicode::DecodeErrorStrategy::STRICT),
                         "illegal UTF8 sequence in string", const RuntimeError&);
}

TEST_CASE("to_string") {
    CHECK_EQ(to_string(std::string("abc")), "\"abc\"");
    CHECK_EQ(to_string(std::string_view("abc")), "\"abc\"");
    CHECK_EQ(to_string("abc"), "\"abc\"");
    CHECK_EQ(to_string("\"\\"), "\"\\\"\\\\\"");
}

TEST_CASE("to_string_for_print") {
    CHECK_EQ(to_string_for_print(std::string("abc")), "abc");
    CHECK_EQ(to_string_for_print(std::string_view("abc")), "abc");
    CHECK_EQ(to_string_for_print("abc"), "abc");
    CHECK_EQ(to_string_for_print(std::string("\\\"")), "\\\"");
    CHECK_EQ(to_string_for_print(std::string_view("\\\"")), "\\\"");
    CHECK_EQ(to_string_for_print("\\\""), "\\\"");
}

TEST_CASE("split") {
    SUBCASE("separator") {
        CHECK_EQ(string::split("12 45", " "), Vector<std::string>({"12", "45"}));
        CHECK_EQ(string::split("12 45 678", " "), Vector<std::string>({"12", "45", "678"}));
        CHECK_EQ(string::split("12345", "34"), Vector<std::string>({"12", "5"}));
        CHECK_EQ(string::split(" 2345", " "), Vector<std::string>({"", "2345"}));
        CHECK_EQ(string::split("12345", ""), Vector<std::string>({"12345"}));
        CHECK_EQ(string::split("12345", "6"), Vector<std::string>({"12345"}));
        CHECK_EQ(string::split("12 34 5", ""), Vector<std::string>({"12 34 5"}));
        CHECK_EQ(string::split(" ", " "), Vector<std::string>({"", ""}));
        CHECK_EQ(string::split("", " "), Vector<std::string>({""}));
        CHECK_EQ(string::split("", ""), Vector<std::string>({""}));
    }

    SUBCASE("whitespace") {
        CHECK_EQ(string::split("12 45"), Vector<std::string>({"12", "45"}));
        CHECK_EQ(string::split("12 45 678"), Vector<std::string>({"12", "45", "678"}));
        CHECK_EQ(string::split("1"), Vector<std::string>({"1"}));

        // TODO: These (and the bytes tests) should match behavior with a provided separator
        CHECK_EQ(string::split(" 2345"), Vector<std::string>({"2345"}));
        CHECK_EQ(string::split(" "), Vector<std::string>());
        CHECK_EQ(string::split(""), Vector<std::string>());
    }

    SUBCASE("multibyte") {
        CHECK_EQ(string::split("𝔘𝔫𝔦𝔠𝔬𝔡𝔢", "𝔦"), Vector<std::string>({"𝔘𝔫", "𝔠𝔬𝔡𝔢"}));
        CHECK_EQ(string::split("𝔘𝔫𝔦𝔠𝔬𝔡𝔢", "i"), Vector<std::string>({"𝔘𝔫𝔦𝔠𝔬𝔡𝔢"}));
        CHECK_EQ(string::split("𝔘𝔫𝔦 𝔠𝔬𝔡𝔢"), Vector<std::string>({"𝔘𝔫𝔦", "𝔠𝔬𝔡𝔢"}));
    }
}

TEST_CASE("split1") {
    SUBCASE("separator") {
        CHECK_EQ(string::split1("12 45", " "), tuple::make("12"s, "45"s));
        CHECK_EQ(string::split1("12 45 678", " "), tuple::make("12"s, "45 678"s));
        CHECK_EQ(string::split1("12345", "34"), tuple::make("12"s, "5"s));
        CHECK_EQ(string::split1(" 2345", " "), tuple::make(""s, "2345"s));
        CHECK_EQ(string::split1("12345", ""), tuple::make(""s, "12345"s));
        CHECK_EQ(string::split1("12345", "6"), tuple::make("12345"s, ""s));
        CHECK_EQ(string::split1("12 34 5", ""), tuple::make(""s, "12 34 5"s));
        CHECK_EQ(string::split1("1", " "), tuple::make("1"s, ""s));
        CHECK_EQ(string::split1("", "1"), tuple::make(""s, ""s));
        CHECK_EQ(string::split1("", ""), tuple::make(""s, ""s));
    }

    SUBCASE("whitespace") {
        CHECK_EQ(string::split1("12 45"), tuple::make("12"s, "45"s));
        CHECK_EQ(string::split1("12 45 678"), tuple::make("12"s, "45 678"s));
        CHECK_EQ(string::split1(" 2345"), tuple::make(""s, "2345"s));
        CHECK_EQ(string::split1("12345"), tuple::make("12345"s, ""s));
        CHECK_EQ(string::split1(" "), tuple::make(""s, ""s));
        CHECK_EQ(string::split1(""), tuple::make(""s, ""s));
        CHECK_EQ(string::split1("1"), tuple::make("1"s, ""s));
    }
}

TEST_SUITE_END();
