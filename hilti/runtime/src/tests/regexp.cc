// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <tuple>

#include <hilti/rt/doctest.h>
#include <hilti/rt/exception.h>
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

    CHECK_EQ(RegExp("ab+c", regexp::Flags{}).find("xyz"_b), -1);
    CHECK_EQ(RegExp("ab+c", regexp::Flags{}).find("abbbcdef"_b), 1);
    CHECK_EQ(RegExp("ab+c", regexp::Flags{}).find("012abbbc345"_b), 1);

    CHECK_EQ(RegExp("ab+c", regexp::Flags{.no_sub = 1}).find("xyz"_b), -1);
    CHECK_EQ(RegExp("ab+c", regexp::Flags{.no_sub = 1}).find("abbbcdef"_b), 1);
    CHECK_EQ(RegExp("ab+c", regexp::Flags{.no_sub = 1}).find("012abbbc345"_b), 1);

    CHECK_EQ(RegExp("ab+c", regexp::Flags{.anchor = 1}).find("xyz"_b), 0);
    CHECK_EQ(RegExp("ab+c", regexp::Flags{.anchor = 1}).find("abbbcdef"_b), 1);
    CHECK_EQ(RegExp("ab+c", regexp::Flags{.anchor = 1}).find("012abbbc345"_b), 0);

    CHECK_EQ(RegExp("ab+c", regexp::Flags{.anchor = 1, .no_sub = 1}).find("xyz"_b), 0);
    CHECK_EQ(RegExp("ab+c", regexp::Flags{.anchor = 1, .no_sub = 1}).find("abbbcdef"_b), 1);
    CHECK_EQ(RegExp("ab+c", regexp::Flags{.anchor = 1, .no_sub = 1}).find("012abbbc345"_b), 0);
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

    CHECK_EQ(RegExp("ab+c", regexp::Flags{}).findSpan("xyz"_b), std::make_tuple(-1, ""_b));
    CHECK_EQ(RegExp("ab+c", regexp::Flags{}).findSpan("abbbcdef"_b), std::make_tuple(1, "abbbc"_b));
    CHECK_EQ(RegExp("ab+c", regexp::Flags{}).findSpan("012abbbc345"_b), std::make_tuple(1, "abbbc"_b));

    CHECK_THROWS_AS(RegExp("ab+c", regexp::Flags{.no_sub = 1}).findSpan("xyz"_b), hilti::rt::NotSupported);

    CHECK_EQ(RegExp("ab+c", regexp::Flags{.anchor = 1}).findSpan("xyz"_b), std::make_tuple(0, ""_b));
    CHECK_EQ(RegExp("ab+c", regexp::Flags{.anchor = 1}).findSpan("abbbcdef"_b), std::make_tuple(1, "abbbc"_b));
    CHECK_EQ(RegExp("ab+c", regexp::Flags{.anchor = 1}).findSpan("012abbbc345"_b), std::make_tuple(0, ""_b));

    CHECK_EQ(RegExp("ab+c", regexp::Flags{.anchor = 1, .no_sub = 1}).findSpan("xyz"_b), std::make_tuple(0, ""_b));
    CHECK_EQ(RegExp("ab+c", regexp::Flags{.anchor = 1, .no_sub = 1}).findSpan("abbbcdef"_b),
             std::make_tuple(1, "abbbc"_b));
    CHECK_EQ(RegExp("ab+c", regexp::Flags{.anchor = 1, .no_sub = 1}).findSpan("012abbbc345"_b),
             std::make_tuple(0, ""_b));
}

TEST_CASE("findGroups") {
    CHECK_EQ(RegExp("abc").findGroups(" abc "_b), Vector<Bytes>({"abc"_b}));
    CHECK_EQ(RegExp("123").findGroups(" abc "_b), Vector<Bytes>());

    CHECK_THROWS_WITH_AS(RegExp(std::vector<std::string>({"abc", "123"})).findGroups("abc"_b),
                         "cannot capture groups during set matching", const NotSupported&);

    CHECK_EQ(RegExp("(a)bc").findGroups(" abc "_b), Vector<Bytes>({"abc"_b, "a"_b}));

    CHECK_EQ(RegExp("a(b*)c(d.f)g", regexp::Flags{}).findGroups("xyz"_b), Vector<Bytes>());
    CHECK_EQ(RegExp("a(b*)c(d.f)g", regexp::Flags{}).findGroups("abbbcdefg"_b),
             Vector<Bytes>({"abbbcdefg"_b, "bbb"_b, "def"_b}));
    CHECK_EQ(RegExp("a(b*)c(d.f)g", regexp::Flags{}).findGroups("012abbbcdefg345"_b),
             Vector<Bytes>({"abbbcdefg"_b, "bbb"_b, "def"_b}));

    CHECK_THROWS_AS(RegExp("a(b+)c(d.f)g", regexp::Flags{.no_sub = 1}).findGroups("xyz"_b), hilti::rt::NotSupported);

    CHECK_EQ(RegExp("a(b+)c(d.f)g", regexp::Flags{.anchor = 1}).findGroups("xyz"_b), Vector<Bytes>());
    CHECK_EQ(RegExp("a(b+)c(d.f)g", regexp::Flags{.anchor = 1}).findGroups("abbbcdefg"_b),
             Vector<Bytes>({"abbbcdefg"_b, "bbb"_b, "def"_b}));
    CHECK_EQ(RegExp("a(b+)c(d.f)g", regexp::Flags{.anchor = 1}).findGroups("012abbbcdefg345"_b), Vector<Bytes>());

    CHECK_THROWS_AS(RegExp("a(b+)c(d.f)g", regexp::Flags{.anchor = 1, .no_sub = 1}).findGroups("xyz"_b),
                    hilti::rt::NotSupported);
}

TEST_CASE("construct") {
    CHECK_THROWS_WITH_AS(RegExp(std::vector<std::string>()), "trying to compile empty pattern set",
                         const PatternError&);
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
    CHECK_THROWS_WITH_AS(RegExp().tokenMatcher(), "trying to match empty pattern set", const PatternError&);
}

TEST_CASE("advance") {
    SUBCASE("matching semantics") {
        // TODO(bbannier): This should return (1, 3).
        CHECK_EQ(RegExp("123").tokenMatcher().advance("123"_b, false), std::make_tuple(-1, 3));
        CHECK_EQ(RegExp("123").tokenMatcher().advance("123"_b, true), std::make_tuple(1, 3));

        CHECK_EQ(RegExp(std::vector<std::string>({"abc", "123"})).tokenMatcher().advance("123"_b, true),
                 std::make_tuple(2, 3));

        // TODO(bbannier): This should either match immediatetly with (1, 0), or never (0, 0).
        CHECK_EQ(RegExp("").tokenMatcher().advance("123"_b, false), std::make_tuple(-1, 3));

        auto re = RegExp("123").tokenMatcher();
        REQUIRE_EQ(re.advance(""_b, true), std::make_tuple(0, 0));
        CHECK_THROWS_WITH_AS(re.advance("123"_b, true), "matching already complete", const MatchStateReuse&);

        CHECK_THROWS_WITH_AS(regexp::MatchState().advance("123"_b, true),
                             "no regular expression associated with match state", const PatternError&);
        CHECK_THROWS_WITH_AS(regexp::MatchState().advance(Stream("123"_b).view()),
                             "no regular expression associated with match state", const PatternError&);

        const auto re_default = RegExp("a(b+)c(d.f)g", regexp::Flags{});
        const auto re_anchor = RegExp("a(b+)c(d.f)g", regexp::Flags{.anchor = 1});
        const auto re_no_sub = RegExp("a(b+)c(d.f)g", regexp::Flags{.no_sub = 1});
        const auto re_anchor_no_sub = RegExp("a(b+)c(d.f)g", regexp::Flags{.anchor = 1, .no_sub = 1});

        {
            auto ms_default_1 = re_default.tokenMatcher();
            CHECK_EQ(ms_default_1.advance("Xa"_b, false), std::make_tuple(-1, 2));
            CHECK_EQ(ms_default_1.advance("bb"_b, false), std::make_tuple(-1, 2));
            CHECK_EQ(ms_default_1.advance("bc"_b, false), std::make_tuple(-1, 2));
            CHECK_EQ(ms_default_1.advance("de"_b, true), std::make_tuple(-1, 2));
            CHECK_EQ(ms_default_1.advance("fgX"_b, true), std::make_tuple(1, 2));
            CHECK_EQ(ms_default_1.captures(Stream("XabbbcdefgX"_b)), Vector<Bytes>({"abbbcdefg"_b, "bbb"_b, "def"_b}));
        }

        {
            auto ms_default_2 = re_default.tokenMatcher();
            CHECK_EQ(ms_default_2.advance("a"_b, false), std::make_tuple(-1, 1));
            CHECK_EQ(ms_default_2.advance("bb"_b, false), std::make_tuple(-1, 2));
            CHECK_EQ(ms_default_2.advance("bc"_b, false), std::make_tuple(-1, 2));
            CHECK_EQ(ms_default_2.advance("de"_b, false), std::make_tuple(-1, 2));
            CHECK_EQ(ms_default_2.advance("fgX"_b, true), std::make_tuple(1, 2));
            CHECK_EQ(ms_default_2.captures(Stream("abbbcdefg"_b)), Vector<Bytes>({"abbbcdefg"_b, "bbb"_b, "def"_b}));
        }

        {
            auto ms_anchor_1 = re_anchor.tokenMatcher();
            CHECK_EQ(ms_anchor_1.advance("Xa"_b, false), std::make_tuple(0, 0));
            CHECK_EQ(ms_anchor_1.captures(Stream("XabbbcdefgX"_b)), Vector<Bytes>());
        }

        {
            auto ms_anchor_2 = re_anchor.tokenMatcher();
            CHECK_EQ(ms_anchor_2.advance("a"_b, false), std::make_tuple(-1, 1));
            CHECK_EQ(ms_anchor_2.advance("bb"_b, false), std::make_tuple(-1, 2));
            CHECK_EQ(ms_anchor_2.advance("bc"_b, false), std::make_tuple(-1, 2));
            CHECK_EQ(ms_anchor_2.advance("de"_b, false), std::make_tuple(-1, 2));
            CHECK_EQ(ms_anchor_2.advance("fgX"_b, true), std::make_tuple(1, 2));
            CHECK_EQ(ms_anchor_2.captures(Stream("abbbcdefg"_b)), Vector<Bytes>({"abbbcdefg"_b, "bbb"_b, "def"_b}));
        }

        {
            auto ms_no_sub_1 = re_no_sub.tokenMatcher();
            CHECK_EQ(ms_no_sub_1.advance("Xa"_b, false), std::make_tuple(-1, 2));
            CHECK_EQ(ms_no_sub_1.advance("bb"_b, false), std::make_tuple(-1, 2));
            CHECK_EQ(ms_no_sub_1.advance("bc"_b, false), std::make_tuple(-1, 2));
            CHECK_EQ(ms_no_sub_1.advance("de"_b, true), std::make_tuple(-1, 2));
            CHECK_EQ(ms_no_sub_1.advance("fgX"_b, true), std::make_tuple(1, 2));
            CHECK_EQ(ms_no_sub_1.captures(Stream("XabbbcdefgX"_b)), Vector<Bytes>());
        }

        {
            auto ms_no_sub_2 = re_no_sub.tokenMatcher();
            CHECK_EQ(ms_no_sub_2.advance("a"_b, false), std::make_tuple(-1, 1));
            CHECK_EQ(ms_no_sub_2.advance("bb"_b, false), std::make_tuple(-1, 2));
            CHECK_EQ(ms_no_sub_2.advance("bc"_b, false), std::make_tuple(-1, 2));
            CHECK_EQ(ms_no_sub_2.advance("de"_b, false), std::make_tuple(-1, 2));
            CHECK_EQ(ms_no_sub_2.advance("fgX"_b, true), std::make_tuple(1, 2));
            CHECK_EQ(ms_no_sub_2.captures(Stream("XabbbcdefgX"_b)), Vector<Bytes>());
        }

        {
            auto ms_anchor_no_sub_1 = re_anchor_no_sub.tokenMatcher();
            CHECK_EQ(ms_anchor_no_sub_1.advance("Xa"_b, false), std::make_tuple(0, 0));
            CHECK_EQ(ms_anchor_no_sub_1.captures(Stream("XabbbcdefgX"_b)), Vector<Bytes>());
        }

        {
            auto ms_anchor_no_sub_2 = re_anchor_no_sub.tokenMatcher();
            CHECK_EQ(ms_anchor_no_sub_2.advance("a"_b, false), std::make_tuple(-1, 1));
            CHECK_EQ(ms_anchor_no_sub_2.advance("bb"_b, false), std::make_tuple(-1, 2));
            CHECK_EQ(ms_anchor_no_sub_2.advance("bc"_b, false), std::make_tuple(-1, 2));
            CHECK_EQ(ms_anchor_no_sub_2.advance("de"_b, false), std::make_tuple(-1, 2));
            CHECK_EQ(ms_anchor_no_sub_2.advance("fgX"_b, true), std::make_tuple(1, 2));
            CHECK_EQ(ms_anchor_no_sub_2.captures(Stream("XabbbcdefgX"_b)), Vector<Bytes>());
        }

        // Check that anchored patterns stop when current match cannot be possible expanded anymore.
        auto http_re_anchor = RegExp("[ \\t]+", regexp::Flags{.anchor = 1});
        auto http_ms_anchor = http_re_anchor.tokenMatcher();
        CHECK_EQ(http_ms_anchor.advance(" /post HTTP/1.1"_b, false), std::make_tuple(1, 1));

        auto http_re_anchor_sub = RegExp("[ \\t]+", regexp::Flags{.anchor = 1, .no_sub = 1});
        auto http_ms_anchor_sub = http_re_anchor_sub.tokenMatcher();
        CHECK_EQ(http_ms_anchor_sub.advance(" /post HTTP/1.1"_b, false), std::make_tuple(1, 1));
    }

    SUBCASE("on set") {
        const auto patterns = std::vector<std::string>({"a(b+cx){#10}", "a(b+cy){#20}"});
        const auto re_default = RegExp(patterns, regexp::Flags{});
        const auto re_anchor = RegExp(patterns, regexp::Flags{.anchor = 1});
        const auto re_no_sub = RegExp(patterns, regexp::Flags{.no_sub = 1});
        const auto re_anchor_no_sub = RegExp(patterns, regexp::Flags{.anchor = 1, .no_sub = 1});

        {
            auto ms_default_1 = re_default.tokenMatcher();
            CHECK_EQ(ms_default_1.advance("Xabbc"_b, false), std::make_tuple(-1, 5));
            CHECK_EQ(ms_default_1.advance("yX"_b, true), std::make_tuple(20, 1));
            CHECK_EQ(ms_default_1.captures(Stream("XabbcyX"_b)), Vector<Bytes>({"abbcy"_b, "bbcy"_b}));
        }

        {
            auto ms_default_2 = re_default.tokenMatcher();
            CHECK_EQ(ms_default_2.advance("abbc"_b, false), std::make_tuple(-1, 4));
            CHECK_EQ(ms_default_2.advance("yX"_b, true), std::make_tuple(20, 1));
            CHECK_EQ(ms_default_2.captures(Stream("abbcyX"_b)), Vector<Bytes>({"abbcy"_b, "bbcy"_b}));
        }

        {
            auto ms_anchor_1 = re_anchor.tokenMatcher();
            CHECK_EQ(ms_anchor_1.advance("Xabbc"_b, false), std::make_tuple(0, 0));
            CHECK_EQ(ms_anchor_1.captures(Stream("XabbcyX"_b)), Vector<Bytes>({}));
        }

        {
            auto ms_anchor_2 = re_anchor.tokenMatcher();
            CHECK_EQ(ms_anchor_2.advance("abbc"_b, false), std::make_tuple(-1, 4));
            CHECK_EQ(ms_anchor_2.advance("yX"_b, true), std::make_tuple(20, 1));
            CHECK_EQ(ms_anchor_2.captures(Stream("abbcyX"_b)), Vector<Bytes>({"abbcy"_b, "bbcy"_b}));
        }

        {
            auto ms_no_sub_1 = re_no_sub.tokenMatcher();
            CHECK_EQ(ms_no_sub_1.advance("Xabbc"_b, false), std::make_tuple(-1, 5));
            CHECK_EQ(ms_no_sub_1.advance("yX"_b, true), std::make_tuple(20, 1));
            CHECK_EQ(ms_no_sub_1.captures(Stream("XabbcyX"_b)), Vector<Bytes>({}));
        }

        {
            auto ms_no_sub_2 = re_no_sub.tokenMatcher();
            CHECK_EQ(ms_no_sub_2.advance("abbc"_b, false), std::make_tuple(-1, 4));
            CHECK_EQ(ms_no_sub_2.advance("yX"_b, true), std::make_tuple(20, 1));
            CHECK_EQ(ms_no_sub_2.captures(Stream("abbcyX"_b)), Vector<Bytes>({}));
        }

        {
            auto ms_anchor_no_sub_1 = re_anchor_no_sub.tokenMatcher();
            CHECK_EQ(ms_anchor_no_sub_1.advance("Xabbc"_b, false), std::make_tuple(0, 0));
            CHECK_EQ(ms_anchor_no_sub_1.captures(Stream("XabbcyX"_b)), Vector<Bytes>({}));
        }

        {
            auto ms_anchor_no_sub_2 = re_anchor_no_sub.tokenMatcher();
            CHECK_EQ(ms_anchor_no_sub_2.advance("abbc"_b, false), std::make_tuple(-1, 4));
            CHECK_EQ(ms_anchor_no_sub_2.advance("yX"_b, true), std::make_tuple(20, 1));
            CHECK_EQ(ms_anchor_no_sub_2.captures(Stream("abbcyX"_b)), Vector<Bytes>({}));
        }
    }

    SUBCASE("advance on limited view") {
        const auto input = "1234567890"_b;

        const auto stream = Stream(input);
        const auto view = stream.view();

        const auto limit = 5;
        const auto limited = view.limit(limit);
        REQUIRE_EQ(limited.size(), limit);

        SUBCASE("match until limit") {
            // Match a regexp ending in a wildcard so it could match the entire input.
            auto&& [rc, unconsumed] = RegExp("123.*").tokenMatcher().advance(limited);

            CHECK_EQ(rc, -1);           // Could consume more data.
            CHECK_EQ(unconsumed, ""_b); // Should have consumed entire input.
            CHECK_EQ(unconsumed.offset(), limit);
        }

        SUBCASE("no match in limit") {
            // Match a regexp matching the input, but not the passed, limited view.
            auto&& [rc, unconsumed] = RegExp(input.data()).tokenMatcher().advance(limited);

            CHECK_EQ(rc, -1); // No match found yet in available, limited data.
        }
    }
}

TEST_CASE("reassign") {
    SUBCASE("inherits state") {
        const auto re = RegExp("123");

        // Create and complete a matcher.
        auto ms1 = re.tokenMatcher();
        REQUIRE_EQ(ms1.advance("123"_b, true), std::make_tuple(1, 3));
        REQUIRE_THROWS_WITH_AS(ms1.advance("123"_b, true), "matching already complete", const MatchStateReuse&);

        // After assigning from a fresh value the matcher can match again.
        ms1 = re.tokenMatcher();
        CHECK_EQ(ms1.advance("123"_b, true), std::make_tuple(1, 3));

        // A matcher copy-constructed from an completed matcher is also completed.
        REQUIRE_THROWS_WITH_AS(ms1.advance("123"_b, true), "matching already complete", const MatchStateReuse&);
        auto ms2(std::move(ms1));
        CHECK_THROWS_WITH_AS(ms2.advance("123"_b, true), "matching already complete", const MatchStateReuse&);

        // Same is true if matching on a different input type.
        REQUIRE_THROWS_WITH_AS(ms2.advance("123"_b, true), "matching already complete", const MatchStateReuse&);
        auto ms3(std::move(ms2));
        CHECK_THROWS_WITH_AS(ms3.advance(Stream("123"_b).view()), "matching already complete", const MatchStateReuse&);
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
