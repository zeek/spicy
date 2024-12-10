// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/rt/doctest.h>
#include <hilti/rt/types/string.h>
#include <hilti/rt/types/vector.h>
#include <hilti/rt/unicode.h>

using namespace hilti::rt;

TEST_SUITE_BEGIN("string");

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
        CHECK_EQ(string::split1("12 45", " "), std::make_tuple("12", "45"));
        CHECK_EQ(string::split1("12 45 678", " "), std::make_tuple("12", "45 678"));
        CHECK_EQ(string::split1("12345", "34"), std::make_tuple("12", "5"));
        CHECK_EQ(string::split1(" 2345", " "), std::make_tuple("", "2345"));
        CHECK_EQ(string::split1("12345", ""), std::make_tuple("", "12345"));
        CHECK_EQ(string::split1("12345", "6"), std::make_tuple("12345", ""));
        CHECK_EQ(string::split1("12 34 5", ""), std::make_tuple("", "12 34 5"));
        CHECK_EQ(string::split1("1", " "), std::make_tuple("1", ""));
        CHECK_EQ(string::split1("", "1"), std::make_tuple("", ""));
        CHECK_EQ(string::split1("", ""), std::make_tuple("", ""));
    }

    SUBCASE("whitespace") {
        CHECK_EQ(string::split1("12 45"), std::make_tuple("12", "45"));
        CHECK_EQ(string::split1("12 45 678"), std::make_tuple("12", "45 678"));
        CHECK_EQ(string::split1(" 2345"), std::make_tuple("", "2345"));
        CHECK_EQ(string::split1("12345"), std::make_tuple("12345", ""));
        CHECK_EQ(string::split1(" "), std::make_tuple("", ""));
        CHECK_EQ(string::split1(""), std::make_tuple("", ""));
        CHECK_EQ(string::split1("1"), std::make_tuple("1", ""));
    }
}

TEST_SUITE_END();
