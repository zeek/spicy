// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <tuple>

#include <hilti/rt/types/bytes.h>
#include <hilti/rt/types/integer.h>
#include <hilti/rt/types/regexp.h>
#include <hilti/rt/types/stream.h>

using namespace hilti::rt;
using namespace hilti::rt::bytes::literals;

namespace std {
template<typename A, typename B>
std::ostream& operator<<(std::ostream& stream, const std::tuple<A, B>& xs) {
    return stream << '[' << to_string(std::get<0>(xs)) << ", " << to_string(std::get<1>(xs)) << ']';
}
} // namespace std

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

TEST_CASE("findSpan") {
    CHECK_EQ(RegExp("abc").findSpan("abc"_b), std::make_tuple(1, "abc"_b));
    CHECK_EQ(RegExp("abc").findSpan(" abc"_b), std::make_tuple(1, "abc"_b));
    CHECK_EQ(RegExp("abc").findSpan("abc "_b), std::make_tuple(1, "abc"_b));
    CHECK_EQ(RegExp("abc").findSpan(" abc "_b), std::make_tuple(1, "abc"_b));

    CHECK_EQ(RegExp("^abc$").findSpan("abc"_b), std::make_tuple(1, "abc"_b));
    CHECK_EQ(RegExp("abc$").findSpan("123"_b), std::make_tuple(-1, ""_b));
    // TODO(bbannier): This should never match and return `0`.
    CHECK_EQ(RegExp("^abc$").findSpan("123"_b), std::make_tuple(-1, ""_b));

    CHECK_EQ(RegExp(std::vector<std::string>({"abc", "123"})).findSpan(" abc "_b), std::make_tuple(1, "abc"_b));
    CHECK_EQ(RegExp(std::vector<std::string>({"abc", "123"})).findSpan(" 123 "_b), std::make_tuple(2, "123"_b));

    CHECK_EQ(RegExp(std::vector<std::string>({"abc", "123"})).find(""_b), -1);

    // Ambiguous case, captured here to ensure consistency.
    CHECK_EQ(RegExp(std::vector<std::string>({"abc", "abc"})).findSpan(" abc "_b), std::make_tuple(1, "abc"_b));
}

TEST_CASE("findGroups") {
    CHECK_EQ(RegExp("abc").findGroups(" abc "_b), Vector<Bytes>({"abc"_b}));
    CHECK_EQ(RegExp("123").findGroups(" abc "_b), Vector<Bytes>());

    CHECK_THROWS_WITH_AS(RegExp(std::vector<std::string>({"abc", "123"})).findGroups("abc"_b),
                         "cannot capture groups during set matching", const regexp::NotSupported&);

    CHECK_EQ(RegExp("(a)bc").findGroups(" abc "_b), Vector<Bytes>({"abc"_b, "a"_b}));
}

TEST_CASE("construct") {
    CHECK_THROWS_WITH_AS(RegExp(std::vector<std::string>()), "trying to compile empty pattern set",
                         const regexp::PatternError&);
}

TEST_CASE("binary data") {
    CHECK_GT(RegExp("\xf0\xfe\xff").find("\xf0\xfe\xff"_b), 0);    // Pass in raw data directly.
    CHECK_GT(RegExp("\\xF0\\xFe\\xff").find("\xf0\xfe\xff"_b), 0); // Let the ctor unescape

    auto x = RegExp("[\\x7F\\x80]*").findSpan("\x7f\x80\x7f\x80$$$"_b);
    CHECK_GT(std::get<0>(x), 0);
    CHECK_EQ(std::get<1>(x).size(), 4); // check for expected length of match

    x = RegExp("abc\\x00def").findSpan("$$abc\000def%%"_b);
    CHECK_GT(std::get<0>(x), 0);
    CHECK_EQ(std::get<1>(x).size(), 7); // check for expected length of match

    // Try escaped data & pattern, which will be matched literally as ASCII characters.
    CHECK_GT(RegExp("\\\\xFF\\\\xFF").find("\\xFF\\xFF"_b), 0);
}

TEST_SUITE_END();

TEST_SUITE_BEGIN("MatchState");

TEST_CASE("construct") {
    CHECK_THROWS_WITH_AS(RegExp().tokenMatcher(), "trying to match empty pattern set", const regexp::PatternError&);
}

TEST_CASE("advance") {
    // TODO(bbannier): This should return (1, 3).
    CHECK_EQ(RegExp("123").tokenMatcher().advance("123"_b, false), std::make_tuple(-1, 3));
    CHECK_EQ(RegExp("123").tokenMatcher().advance("123"_b, true), std::make_tuple(1, 3));

    CHECK_EQ(RegExp(std::vector<std::string>({"abc", "123"})).tokenMatcher().advance("123"_b, true),
             std::make_tuple(2, 3));

    // TODO(bbannier): This should either match immediatetly with (1, 0), or never (0, 0).
    CHECK_EQ(RegExp("").tokenMatcher().advance("123"_b, false), std::make_tuple(-1, 3));

    auto re = RegExp("123").tokenMatcher();
    REQUIRE_EQ(re.advance(""_b, true), std::make_tuple(0, 0));
    CHECK_THROWS_WITH_AS(re.advance("123"_b, true), "matching already complete", const regexp::MatchStateReuse&);

    CHECK_THROWS_WITH_AS(regexp::MatchState().advance("123"_b, true),
                         "no regular expression associated with match state", const regexp::PatternError&);
    CHECK_THROWS_WITH_AS(regexp::MatchState().advance(Stream("123"_b).view()),
                         "no regular expression associated with match state", const regexp::PatternError&);
}

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

TEST_CASE("reassign") {
    SUBCASE("inherits state") {
        const auto re = RegExp("123");

        // Create and complete a matcher.
        auto ms1 = re.tokenMatcher();
        REQUIRE_EQ(ms1.advance("123"_b, true), std::make_tuple(1, 3));
        REQUIRE_THROWS_WITH_AS(ms1.advance("123"_b, true), "matching already complete", const regexp::MatchStateReuse&);

        // After assigning from a fresh value the matcher can match again.
        ms1 = re.tokenMatcher();
        CHECK_EQ(ms1.advance("123"_b, true), std::make_tuple(1, 3));

        // A matcher copy-constructed from an completed matcher is also completed.
        REQUIRE_THROWS_WITH_AS(ms1.advance("123"_b, true), "matching already complete", const regexp::MatchStateReuse&);
        auto ms2(std::move(ms1));
        CHECK_THROWS_WITH_AS(ms2.advance("123"_b, true), "matching already complete", const regexp::MatchStateReuse&);

        // Same is true if matching on a different input type.
        REQUIRE_THROWS_WITH_AS(ms2.advance("123"_b, true), "matching already complete", const regexp::MatchStateReuse&);
        auto ms3(std::move(ms2));
        CHECK_THROWS_WITH_AS(ms3.advance(Stream("123"_b).view()), "matching already complete",
                             const regexp::MatchStateReuse&);
    }

    SUBCASE("no copy from REG_STD_MATCHER regexp") {
        const auto re = RegExp("123", regexp::Flags({.no_sub = 0}));
        const auto ms1 = re.tokenMatcher();

        CHECK_THROWS_WITH_AS(regexp::MatchState{ms1}, "cannot copy match state of regexp with sub-expressions support",
                             const InvalidArgument&);

        auto ms2 = regexp::MatchState();
        CHECK_THROWS_WITH_AS(ms2.operator=(ms1), "cannot copy match state of regexp with sub-expressions support",
                             const InvalidArgument&);
    }

    SUBCASE("copy from non-REG_STD_MATCHER regexp") {
        const auto re = RegExp("123", regexp::Flags({.no_sub = 1}));
        const auto ms1 = re.tokenMatcher();

        CHECK_NOTHROW(regexp::MatchState{ms1});

        auto ms2 = regexp::MatchState();
        CHECK_NOTHROW(ms2.operator=(ms1));
    }
}

TEST_SUITE_END();
