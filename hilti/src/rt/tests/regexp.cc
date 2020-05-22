// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <tuple>

#include <doctest/doctest.h>

#include <hilti/rt/types/bytes.h>
#include <hilti/rt/types/integer.h>
#include <hilti/rt/types/regexp.h>
#include <hilti/rt/types/stream.h>

using namespace hilti::rt;
using namespace hilti::rt::bytes::literals;

TEST_SUITE_BEGIN("RegExp");

TEST_CASE("find") {
    CHECK_GT(RegExp("abc").find("abc"_b), 0);
    CHECK_GT(RegExp("abc").find(" abc"_b), 0);
    CHECK_GT(RegExp("abc").find("abc "_b), 0);
    CHECK_GT(RegExp("abc").find(" abc "_b), 0);

    CHECK_EQ(RegExp("^abc$").find("abc"_b), 1);
    CHECK_EQ(RegExp("abc$").find("123"_b), -1);
    // TODO(bbannier): This should never match and return `0`.
    CHECK_EQ(RegExp("^abc$").find("123"_b), -1);

    CHECK_EQ(RegExp(std::vector<std::string>({"abc", "123"})).find(" abc "_b), 1);
    CHECK_EQ(RegExp(std::vector<std::string>({"abc", "123"})).find(" 123 "_b), 2);

    CHECK_EQ(RegExp(std::vector<std::string>({"abc", "123"})).find(""_b), -1);

    // Ambiguous case, captured here to ensure consistency.
    CHECK_EQ(RegExp(std::vector<std::string>({"abc", "abc"})).find(" abc "_b), 1);
}

TEST_SUITE_END();

TEST_SUITE_BEGIN("MatchState");

TEST_CASE("advance on limited view") {
    const auto input = "1234567890"_b;

    const auto stream = Stream(input);
    const auto view = stream.view();

    const auto limit = 5;
    const auto limited = view.limit(limit);
    REQUIRE_EQ(limited.size(), limit);

    SUBCASE("match until limit") {
        // Match a regexp ending in a wildcard so it could match the entire input.
        auto&& [rc, unconsumed] = RegExp("123.*").tokenMatcher().advance(limited);

        CHECK_EQ(rc, 1);             // Match found, cannot consume more data.
        CHECK(unconsumed.isEmpty()); // Should have consumed entire input.
        CHECK_EQ(unconsumed.offset(), limit);
    }

    SUBCASE("no match in limit") {
        // Match a regexp matching the input, but not the passed, limited view.
        auto&& [rc, unconsumed] = RegExp(input.data()).tokenMatcher().advance(limited);

        CHECK_EQ(rc, -1); // No match found yet in available, limited data.
    }
}

TEST_SUITE_END();
