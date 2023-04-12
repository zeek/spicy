// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/rt/doctest.h>
#include <hilti/rt/types/string.h>

using namespace hilti::rt;

TEST_SUITE_BEGIN("string");

TEST_CASE("lower") {
    CHECK_EQ(string::lower(""), "");
    CHECK_EQ(string::lower("123Abc"), "123abc");
    CHECK_EQ(string::lower("GÄNSEFÜẞCHEN"), "gänsefüßchen");
    CHECK_EQ(string::lower("\xc3\x28" "aBcD", string::DecodeErrorStrategy::REPLACE), "\ufffd(abcd");
    CHECK_EQ(string::lower("\xc3\x28" "aBcD", string::DecodeErrorStrategy::IGNORE), "(abcd");
    CHECK_THROWS_WITH_AS(string::lower("\xc3\x28" "aBcD", string::DecodeErrorStrategy::STRICT), "illegal UTF8 sequence in string", const RuntimeError&);
}

TEST_CASE("size") {
    CHECK_EQ(string::size(""), 0U);
    CHECK_EQ(string::size("123Abc"), 6U);
    CHECK_EQ(string::size("Gänsefüßchen"), 12U);
    CHECK_EQ(string::size("\xc3\x28" "aBcD", string::DecodeErrorStrategy::REPLACE), 6U);
    CHECK_EQ(string::size("\xc3\x28" "aBcD", string::DecodeErrorStrategy::IGNORE), 5U);
    CHECK_THROWS_WITH_AS(string::size("\xc3\x28" "aBcD", string::DecodeErrorStrategy::STRICT), "illegal UTF8 sequence in string", const RuntimeError&);
}

TEST_CASE("upper") {
    CHECK_EQ(string::upper(""), "");
    CHECK_EQ(string::upper("123Abc"), "123ABC");
    CHECK_EQ(string::upper("Gänsefüßchen"), "GÄNSEFÜẞCHEN");
    CHECK_EQ(string::upper("\xc3\x28" "aBcD", string::DecodeErrorStrategy::REPLACE), "\ufffd(ABCD");
    CHECK_EQ(string::upper("\xc3\x28" "aBcD", string::DecodeErrorStrategy::IGNORE), "(ABCD");
    CHECK_THROWS_WITH_AS(string::upper("\xc3\x28" "aBcD", string::DecodeErrorStrategy::STRICT), "illegal UTF8 sequence in string", const RuntimeError&);
}

TEST_SUITE_END();
