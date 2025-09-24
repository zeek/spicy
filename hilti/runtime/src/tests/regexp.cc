// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <tuple>

#include <hilti/rt/exception.h>
#include <hilti/rt/extension-points.h>
#include <hilti/rt/safe-int.h>
#include <hilti/rt/types/bytes.h>
#include <hilti/rt/types/integer.h>
#include <hilti/rt/types/regexp.h>
#include <hilti/rt/types/stream.h>
#include <hilti/rt/types/tuple.h>

using namespace hilti::rt;
using namespace hilti::rt::bytes::literals;

TEST_SUITE_BEGIN("RegExp");

inline auto operator""_p(const char* str, size_t size) { return hilti::rt::regexp::Pattern(std::string(str, size)); }

TEST_CASE("match") {
    SUBCASE("min-matcher") {
        CHECK_GT(RegExp("abc"_p, regexp::Flags{.no_sub = 1}).match("abc"_b), 0);
        CHECK_GT(RegExp(".*abc"_p, regexp::Flags{.no_sub = 1}).match(" abc"_b), 0);
        CHECK_GT(RegExp("abc"_p, regexp::Flags{.no_sub = 1}).match("abc "_b), 0);
        CHECK_GT(RegExp(".*abc"_p, regexp::Flags{.no_sub = 1}).match(" abc "_b), 0);

        CHECK_EQ(RegExp("^abc$"_p, regexp::Flags{.no_sub = 1}).match("abc"_b), 1);
        CHECK_EQ(RegExp("abc$"_p, regexp::Flags{.no_sub = 1}).match("123"_b), 0);
        CHECK_EQ(RegExp("^abc$"_p, regexp::Flags{.no_sub = 1}).match("123"_b), 0);

        CHECK_EQ(RegExp({".*abc"_p, ".*123"_p}, regexp::Flags{.no_sub = 1}).match(" abc "_b), 1);
        CHECK_EQ(RegExp({".*abc"_p, ".*123"_p}, regexp::Flags{.no_sub = 1}).match(" 123 "_b), 2);

        CHECK_EQ(RegExp({"abc"_p, "123"_p}, regexp::Flags{.no_sub = 1}).match(""_b), -1);

        // Ambiguous case, captured here to ensure consistency.
        CHECK_EQ(RegExp({".*abc"_p, ".*abc"_p}, regexp::Flags{.no_sub = 1}).match(" abc "_b), 1);

        CHECK_EQ(RegExp("ab+c"_p, regexp::Flags{.no_sub = 1}).match("xyz"_b), 0);
        CHECK_EQ(RegExp("ab+c"_p, regexp::Flags{.no_sub = 1}).match("abbbcdef"_b), 1);
        CHECK_EQ(RegExp("ab+c"_p, regexp::Flags{.no_sub = 1}).match("012abbbc345"_b), 0);

        CHECK_EQ(RegExp("ab+c"_p, regexp::Flags{.no_sub = 1}).match("xyz"_b), 0);
        CHECK_EQ(RegExp("ab+c"_p, regexp::Flags{.no_sub = 1}).match("abbbcdef"_b), 1);
        CHECK_EQ(RegExp("ab+c"_p, regexp::Flags{.no_sub = 1}).match("012abbbc345"_b), 0);
    }

    SUBCASE("std-matcher") {
        CHECK_GT(RegExp("abc"_p, regexp::Flags{.use_std = 1}).match("abc"_b), 0);
        CHECK_GT(RegExp(".*abc"_p, regexp::Flags{.use_std = 1}).match(" abc"_b), 0);
        CHECK_GT(RegExp("abc"_p, regexp::Flags{.use_std = 1}).match("abc "_b), 0);
        CHECK_GT(RegExp(".*abc"_p, regexp::Flags{.use_std = 1}).match(" abc "_b), 0);

        CHECK_EQ(RegExp("^abc$"_p, regexp::Flags{.use_std = 1}).match("abc"_b), 1);
        CHECK_EQ(RegExp("abc$"_p, regexp::Flags{.use_std = 1}).match("123"_b), 0);
        CHECK_EQ(RegExp("^abc$"_p, regexp::Flags{.use_std = 1}).match("123"_b), 0);

        CHECK_EQ(RegExp({".*abc"_p, ".*123"_p}, regexp::Flags{.use_std = 1}).match(" abc "_b), 1);
        CHECK_EQ(RegExp({".*abc"_p, ".*123"_p}, regexp::Flags{.use_std = 1}).match(" 123 "_b), 2);

        CHECK_EQ(RegExp({"abc"_p, "123"_p}, regexp::Flags{.use_std = 1}).match(""_b), -1);

        // Ambiguous case, captured here to ensure consistency.
        CHECK_EQ(RegExp({".*abc"_p, ".*abc"_p}, regexp::Flags{.use_std = 1}).match(" abc "_b), 1);

        CHECK_EQ(RegExp("ab+c"_p, regexp::Flags{.use_std = 1}).match("xyz"_b), 0);
        CHECK_EQ(RegExp("ab+c"_p, regexp::Flags{.use_std = 1}).match("abbbcdef"_b), 1);
        CHECK_EQ(RegExp("ab+c"_p, regexp::Flags{.use_std = 1}).match("012abbbc345"_b), 0);

        CHECK_EQ(RegExp("ab+c"_p, regexp::Flags{.use_std = 1}).match("xyz"_b), 0);
        CHECK_EQ(RegExp("ab+c"_p, regexp::Flags{.use_std = 1}).match("abbbcdef"_b), 1);
        CHECK_EQ(RegExp("ab+c"_p, regexp::Flags{.use_std = 1}).match("012abbbc345"_b), 0);
    }
}

TEST_CASE("find") {
    SUBCASE("empty needle") { CHECK_EQ(RegExp("abc"_p, regexp::Flags{.no_sub = 1}).find(""_b), tuple::make(-1, ""_b)); }

    SUBCASE("min-matcher") {
        CHECK_EQ(RegExp("abc"_p, regexp::Flags{.no_sub = 1}).find("abc"_b), tuple::make(1, "abc"_b));
        CHECK_EQ(RegExp("abc"_p, regexp::Flags{.no_sub = 1}).find(" abc"_b), tuple::make(1, "abc"_b));
        CHECK_EQ(RegExp("abc"_p, regexp::Flags{.no_sub = 1}).find("abc "_b), tuple::make(1, "abc"_b));
        CHECK_EQ(RegExp("abc"_p, regexp::Flags{.no_sub = 1}).find(" abc "_b), tuple::make(1, "abc"_b));

        CHECK_EQ(RegExp("^abc$"_p, regexp::Flags{.no_sub = 1}).find("abc"_b), tuple::make(1, "abc"_b));
        CHECK_EQ(RegExp("abc$"_p, regexp::Flags{.no_sub = 1}).find("123"_b), tuple::make(-1, ""_b));
        // TODO(bbannier): This should never match and return `0`.
        CHECK_EQ(RegExp("^abc$"_p, regexp::Flags{.no_sub = 1}).find("123"_b), tuple::make(-1, ""_b));

        CHECK_EQ(RegExp({"abc"_p, "123"_p}, regexp::Flags{.no_sub = 1}).find(" abc "_b), tuple::make(1, "abc"_b));
        CHECK_EQ(RegExp({"abc"_p, "123"_p}, regexp::Flags{.no_sub = 1}).find(" 123 "_b), tuple::make(2, "123"_b));

        CHECK_EQ(RegExp({"abc"_p, "123"_p}, regexp::Flags{.no_sub = 1}).find(""_b), tuple::make(-1, ""_b));

        // Ambiguous case, captured here to ensure consistency.
        CHECK_EQ(RegExp({"abc"_p, "abc"_p}, regexp::Flags{.no_sub = 1}).find(" abc "_b), tuple::make(1, "abc"_b));

        CHECK_EQ(RegExp("ab+c"_p, regexp::Flags{.no_sub = 1}).find("xyz"_b), tuple::make(-1, ""_b));
        CHECK_EQ(RegExp("ab+c"_p, regexp::Flags{.no_sub = 1}).find("abbbcdef"_b), tuple::make(1, "abbbc"_b));
        CHECK_EQ(RegExp("ab+c"_p, regexp::Flags{.no_sub = 1}).find("012abbbc345"_b), tuple::make(1, "abbbc"_b));

        CHECK_EQ(RegExp("ab+c"_p, regexp::Flags{.no_sub = 1}).find("xyz"_b), tuple::make(-1, ""_b));
        CHECK_EQ(RegExp("ab+c"_p, regexp::Flags{.no_sub = 1}).find("abbbcdef"_b), tuple::make(1, "abbbc"_b));
        CHECK_EQ(RegExp("ab+c"_p, regexp::Flags{.no_sub = 1}).find("012abbbc345"_b), tuple::make(1, "abbbc"_b));

        CHECK_EQ(RegExp("ab+c"_p, regexp::Flags{.no_sub = 1}).find("xyz"_b), tuple::make(-1, ""_b));
        CHECK_EQ(RegExp("ab+c"_p, regexp::Flags{.no_sub = 1}).find("abbbcdef"_b), tuple::make(1, "abbbc"_b));
        CHECK_EQ(RegExp("ab+c"_p, regexp::Flags{.no_sub = 1}).find("012abbbc345"_b), tuple::make(1, "abbbc"_b));

        CHECK_EQ(RegExp("23.*09"_p, regexp::Flags{.no_sub = 1}).find("xxA1234X5678Y0912Bxx"_b),
                 tuple::make(1, "234X5678Y09"_b));
        CHECK_EQ(RegExp("23.*09"_p, regexp::Flags{.no_sub = 1}).find("xxA123X0912Bxx23YY09xx"_b),
                 tuple::make(1, "23X0912Bxx23YY09"_b));
        CHECK_EQ(RegExp("23.*09"_p, regexp::Flags{.no_sub = 1}).find("xxA123X2309YY09xx"_b),
                 tuple::make(1, "23X2309YY09"_b));
    }

    SUBCASE("std-matcher") {
        CHECK_EQ(RegExp("abc"_p, regexp::Flags{.use_std = 1}).find("abc"_b), tuple::make(1, "abc"_b));
        CHECK_EQ(RegExp("abc"_p, regexp::Flags{.use_std = 1}).find(" abc"_b), tuple::make(1, "abc"_b));
        CHECK_EQ(RegExp("abc"_p, regexp::Flags{.use_std = 1}).find("abc "_b), tuple::make(1, "abc"_b));
        CHECK_EQ(RegExp("abc"_p, regexp::Flags{.use_std = 1}).find(" abc "_b), tuple::make(1, "abc"_b));

        CHECK_EQ(RegExp("^abc$"_p, regexp::Flags{.use_std = 1}).find("abc"_b), tuple::make(1, "abc"_b));
        CHECK_EQ(RegExp("abc$"_p, regexp::Flags{.use_std = 1}).find("123"_b), tuple::make(-1, ""_b));
        // TODO(bbannier): This should never match and return `0`.
        CHECK_EQ(RegExp("^abc$"_p, regexp::Flags{.use_std = 1}).find("123"_b), tuple::make(-1, ""_b));

        CHECK_EQ(RegExp({"abc"_p, "123"_p}, regexp::Flags{.use_std = 1}).find(" abc "_b), tuple::make(1, "abc"_b));
        CHECK_EQ(RegExp({"abc"_p, "123"_p}, regexp::Flags{.use_std = 1}).find(" 123 "_b), tuple::make(2, "123"_b));

        CHECK_EQ(RegExp({"abc"_p, "123"_p}, regexp::Flags{.use_std = 1}).find(""_b), tuple::make(-1, ""_b));

        // Ambiguous case, captured here to ensure consistency.
        CHECK_EQ(RegExp({"abc"_p, "abc"_p}, regexp::Flags{.use_std = 1}).find(" abc "_b), tuple::make(1, "abc"_b));

        CHECK_EQ(RegExp("ab+c"_p, regexp::Flags{.use_std = 1}).find("xyz"_b), tuple::make(-1, ""_b));
        CHECK_EQ(RegExp("ab+c"_p, regexp::Flags{.use_std = 1}).find("abbbcdef"_b), tuple::make(1, "abbbc"_b));
        CHECK_EQ(RegExp("ab+c"_p, regexp::Flags{.use_std = 1}).find("012abbbc345"_b), tuple::make(1, "abbbc"_b));

        CHECK_EQ(RegExp("ab+c"_p, regexp::Flags{.use_std = 1}).find("xyz"_b), tuple::make(-1, ""_b));
        CHECK_EQ(RegExp("ab+c"_p, regexp::Flags{.use_std = 1}).find("abbbcdef"_b), tuple::make(1, "abbbc"_b));
        CHECK_EQ(RegExp("ab+c"_p, regexp::Flags{.use_std = 1}).find("012abbbc345"_b), tuple::make(1, "abbbc"_b));

        CHECK_EQ(RegExp("ab+c"_p, regexp::Flags{.use_std = 1}).find("xyz"_b), tuple::make(-1, ""_b));
        CHECK_EQ(RegExp("ab+c"_p, regexp::Flags{.use_std = 1}).find("abbbcdef"_b), tuple::make(1, "abbbc"_b));
        CHECK_EQ(RegExp("ab+c"_p, regexp::Flags{.use_std = 1}).find("012abbbc345"_b), tuple::make(1, "abbbc"_b));

        CHECK_EQ(RegExp("23.*09"_p, regexp::Flags{.use_std = 1}).find("xxA1234X5678Y0912Bxx"_b),
                 tuple::make(1, "234X5678Y09"_b));
        CHECK_EQ(RegExp("23.*09"_p, regexp::Flags{.use_std = 1}).find("xxA123X0912Bxx23YY09xx"_b),
                 tuple::make(1, "23X0912Bxx23YY09"_b));
        CHECK_EQ(RegExp("23.*09"_p, regexp::Flags{.use_std = 1}).find("xxA123X2309YY09xx"_b),
                 tuple::make(1, "23X2309YY09"_b));
    }
}

TEST_CASE("matchGroups") {
    SUBCASE("min-matcher") {
        CHECK_THROWS_WITH_AS(RegExp({"abc"_p, "123"_p}).matchGroups("abc"_b),
                             "cannot capture groups during set matching", const NotSupported&);
    }

    SUBCASE("std-matcher") {
        CHECK_EQ(RegExp(".*abc"_p, regexp::Flags{.use_std = 1}).matchGroups(" abc "_b), Vector<Bytes>({" abc"_b}));
        CHECK_EQ(RegExp("123"_p, regexp::Flags{.use_std = 1}).matchGroups(" abc "_b), Vector<Bytes>());

        CHECK_THROWS_WITH_AS(RegExp({"abc"_p, "123"_p}).matchGroups("abc"_b),
                             "cannot capture groups during set matching", const NotSupported&);

        CHECK_EQ(RegExp(".*(a)bc"_p, regexp::Flags{.use_std = 1}).matchGroups(" abc "_b),
                 Vector<Bytes>({" abc"_b, "a"_b}));

        CHECK_EQ(RegExp("a(b*)c(d.f)g"_p, regexp::Flags{.use_std = 1}).matchGroups("xyz"_b), Vector<Bytes>());
        CHECK_EQ(RegExp("a(b*)c(d.f)g"_p, regexp::Flags{.use_std = 1}).matchGroups("abbbcdefg"_b),
                 Vector<Bytes>({"abbbcdefg"_b, "bbb"_b, "def"_b}));
        CHECK_EQ(RegExp(".*a(b*)c(d.f)g"_p, regexp::Flags{.use_std = 1}).matchGroups("012abbbcdefg345"_b),
                 Vector<Bytes>({"012abbbcdefg"_b, "bbb"_b, "def"_b}));
    }
}

TEST_CASE("binary data") {
    CHECK_GT(RegExp("\xf0\xfe\xff"_p).match("\xf0\xfe\xff"_b), 0);    // Pass in raw data directly.
    CHECK_GT(RegExp("\\xF0\\xFe\\xff"_p).match("\xf0\xfe\xff"_b), 0); // Let the ctor unescape

    auto x = RegExp("[\\x7F\\x80]*"_p).find("\x7f\x80\x7f\x80$$$"_b);
    CHECK_GT(tuple::get<0>(x), 0);
    CHECK_EQ(tuple::get<1>(x).size(), 4); // check for expected length of match

    x = RegExp("abc\\x00def"_p).find("$$abc\000def%%"_b);
    CHECK_GT(tuple::get<0>(x), 0);
    CHECK_EQ(tuple::get<1>(x).size(), 7); // check for expected length of match

    // Try escaped data & pattern, which will be matched literally as ASCII characters.
    CHECK_GT(RegExp("\\\\xFF\\\\xFF"_p).match("\\xFF\\xFF"_b), 0);
}

TEST_SUITE_END();

TEST_SUITE_BEGIN("MatchState");

TEST_CASE("construct") {
    CHECK_THROWS_WITH_AS(RegExp().tokenMatcher(), "trying to match empty pattern set", const PatternError&);
}

TEST_CASE("advance") {
    SUBCASE("matching semantics") {
        CHECK_EQ(RegExp("123"_p).tokenMatcher().advance("123"_b, false), tuple::make(1, 3));
        CHECK_EQ(RegExp("123"_p).tokenMatcher().advance("123"_b, true), tuple::make(1, 3));

        CHECK_EQ(RegExp({"abc"_p, "123"_p}).tokenMatcher().advance("123"_b, true), tuple::make(2, 3));

        CHECK_EQ(RegExp(""_p).tokenMatcher().advance("123"_b, false), tuple::make(1, 0));

        auto re = RegExp("123"_p).tokenMatcher();
        REQUIRE_EQ(re.advance(""_b, true), tuple::make(0, 0));
        CHECK_THROWS_WITH_AS(re.advance("123"_b, true), "matching already complete", const MatchStateReuse&);

        CHECK_THROWS_WITH_AS(regexp::MatchState().advance("123"_b, true),
                             "no regular expression associated with match state", const PatternError&);
        CHECK_THROWS_WITH_AS(regexp::MatchState().advance(Stream("123"_b).view()),
                             "no regular expression associated with match state", const PatternError&);

        const auto re_std = RegExp("a(b+)c(d.f)g"_p, regexp::Flags{.use_std = true});
        const auto re_no_sub = RegExp("a(b+)c(d.f)g"_p, regexp::Flags{.no_sub = true});

        {
            auto ms_std_1 = re_std.tokenMatcher();
            CHECK_EQ(ms_std_1.advance("Xa"_b, false), tuple::make(0, 0));
            CHECK_EQ(ms_std_1.captures(Stream("XabbbcdefgX"_b).view()), Vector<Bytes>());
        }

        {
            auto ms_std_2 = re_std.tokenMatcher();
            CHECK_EQ(ms_std_2.advance("a"_b, false), tuple::make(-1, 1));
            CHECK_EQ(ms_std_2.advance("bb"_b, false), tuple::make(-1, 2));
            CHECK_EQ(ms_std_2.advance("bc"_b, false), tuple::make(-1, 2));
            CHECK_EQ(ms_std_2.advance("de"_b, false), tuple::make(-1, 2));
            CHECK_EQ(ms_std_2.advance("fgX"_b, true), tuple::make(1, 2));
            CHECK_EQ(ms_std_2.captures(Stream("abbbcdefg"_b).view()), Vector<Bytes>({"abbbcdefg"_b, "bbb"_b, "def"_b}));
        }

        {
            auto ms_no_sub_1 = re_no_sub.tokenMatcher();
            CHECK_EQ(ms_no_sub_1.advance("Xa"_b, false), tuple::make(0, 0));
            CHECK_EQ(ms_no_sub_1.captures(Stream("XabbbcdefgX"_b).view()), Vector<Bytes>());
        }

        {
            auto ms_no_sub_2 = re_no_sub.tokenMatcher();
            CHECK_EQ(ms_no_sub_2.advance("a"_b, false), tuple::make(-1, 1));
            CHECK_EQ(ms_no_sub_2.advance("bb"_b, false), tuple::make(-1, 2));
            CHECK_EQ(ms_no_sub_2.advance("bc"_b, false), tuple::make(-1, 2));
            CHECK_EQ(ms_no_sub_2.advance("de"_b, false), tuple::make(-1, 2));
            CHECK_EQ(ms_no_sub_2.advance("fgX"_b, true), tuple::make(1, 2));
            CHECK_EQ(ms_no_sub_2.captures(Stream("XabbbcdefgX"_b).view()), Vector<Bytes>());
        }

        // Check that patterns stop when current match cannot be possible expanded anymore.
        auto http_re_std = RegExp("[ \\t]+"_p, regexp::Flags{.use_std = true});
        auto http_ms_std = http_re_std.tokenMatcher();
        CHECK_EQ(http_ms_std.advance(" /post HTTP/1.1"_b, false), tuple::make(1, 1));

        auto http_re_std_sub = RegExp("[ \\t]+"_p, regexp::Flags{.no_sub = true});
        auto http_ms_std_sub = http_re_std_sub.tokenMatcher();
        CHECK_EQ(http_ms_std_sub.advance(" /post HTTP/1.1"_b, false), tuple::make(1, 1));
    }

    SUBCASE("on set") {
        const auto patterns = regexp::Patterns({{"a(b+cx)", false, 10}, {"a(b+cy)", false, 20}});
        const auto re_std = RegExp(patterns, regexp::Flags{.use_std = true});
        const auto re_no_sub = RegExp(patterns, regexp::Flags{.no_sub = true});

        {
            auto ms_std_1 = re_std.tokenMatcher();
            CHECK_EQ(ms_std_1.advance("Xabbc"_b, false), tuple::make(0, 0));
            CHECK_EQ(ms_std_1.captures(Stream("XabbcyX"_b).view()), Vector<Bytes>({}));
        }

        {
            auto ms_std_2 = re_std.tokenMatcher();
            CHECK_EQ(ms_std_2.advance("abbc"_b, false), tuple::make(-1, 4));
            CHECK_EQ(ms_std_2.advance("yX"_b, true), tuple::make(20, 1));
            CHECK_EQ(ms_std_2.captures(Stream("abbcyX"_b).view()), Vector<Bytes>({"abbcy"_b, "bbcy"_b}));
        }

        {
            auto ms_no_sub_1 = re_no_sub.tokenMatcher();
            CHECK_EQ(ms_no_sub_1.advance("Xabbc"_b, false), tuple::make(0, 0));
            CHECK_EQ(ms_no_sub_1.captures(Stream("XabbcyX"_b).view()), Vector<Bytes>({}));
        }

        {
            auto ms_no_sub_2 = re_no_sub.tokenMatcher();
            CHECK_EQ(ms_no_sub_2.advance("abbc"_b, false), tuple::make(-1, 4));
            CHECK_EQ(ms_no_sub_2.advance("yX"_b, true), tuple::make(20, 1));
            CHECK_EQ(ms_no_sub_2.captures(Stream("abbcyX"_b).view()), Vector<Bytes>({}));
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
            const auto x = RegExp("123.*"_p).tokenMatcher().advance(limited);
            const auto& rc = tuple::get<0>(x);
            const auto& unconsumed = tuple::get<1>(x);

            CHECK_EQ(rc, 1);            // Match found and cannot consume more data.
            CHECK_EQ(unconsumed, ""_b); // Should have consumed entire input.
            CHECK_EQ(unconsumed.offset(), limit);
        }

        SUBCASE("no match in limit") {
            // Match a regexp matching the input, but not the passed, limited view.
            const auto x = RegExp({input.data()}).tokenMatcher().advance(limited);
            const auto& rc = tuple::get<0>(x);

            CHECK_EQ(rc, -1); // No match found yet in available, limited data.
        }
    }

    SUBCASE("advance on view split with match split across blocks") {
        // This is a regression test for GH-860.

        // Construct a stream where the chunk border is exactly on a group we want to match.
        // We freeze the stream to force regex matcher to decide on match immediately.
        auto s = Stream();
        s.append("\n");
        s.append(" ");
        s.freeze();
        REQUIRE_EQ(s.numberOfChunks(), 2);

        CHECK_EQ(RegExp("[ \\n]*"_p, {}).tokenMatcher().advance(s.view()), tuple::make(1, stream::View()));
    }

    SUBCASE("advance with backtracking across chunks of input") {
        const auto re_std = RegExp("abc(123)?"_p, regexp::Flags{.use_std = true});
        auto ms_std_1 = re_std.tokenMatcher();
        CHECK_EQ(ms_std_1.advance("a"_b, false), tuple::make(-1, 1));
        CHECK_EQ(ms_std_1.advance("b"_b, false), tuple::make(-1, 1));
        CHECK_EQ(ms_std_1.advance("c"_b, false), tuple::make(-1, 1));
        CHECK_EQ(ms_std_1.advance("1"_b, false), tuple::make(-1, 1));
        CHECK_EQ(ms_std_1.advance("2"_b, false), tuple::make(-1, 1));
        CHECK_EQ(ms_std_1.advance("X"_b, false), tuple::make(1, -2)); // go back two bytes
    }

    SUBCASE("advance into gap") {
        // This is a regression test for GH-1303.
        auto s = Stream();
        s.append("A");
        s.append(nullptr, 1024);
        s.append("BC");
        s.freeze();

        const auto re = RegExp("(A|B|C)"_p);

        auto cur = s.view();

        // Match on `A`.
        {
            auto [rc, ncur] = re.tokenMatcher().advance(cur);
            CHECK_EQ(rc, 1);
            CHECK_EQ(ncur, stream::View(cur.begin() + 1, cur.end()));
            cur = ncur;
        }

        // Match attempt on gap fails, but leaves `cur` alone.
        CHECK_EQ(cur.offset(), 1);
        CHECK_THROWS_AS(re.tokenMatcher().advance(cur), MissingData);
        CHECK_EQ(cur.offset(), 1);

        // Resynchronize input which should put us just after the gap on `B`.
        cur = cur.advanceToNextData();
        CHECK_EQ(cur.offset(), 1 + 1024);

        // Match on `B`.
        {
            auto [rc, ncur] = re.tokenMatcher().advance(cur);
            CHECK_EQ(rc, 1);
            CHECK_EQ(ncur.offset(), 1 + 1024 + 1);
        }
    }
}

TEST_CASE("reassign") {
    SUBCASE("inherits state") {
        const auto re = RegExp("123"_p);

        // Create and complete a matcher.
        auto ms1 = re.tokenMatcher();
        REQUIRE_EQ(ms1.advance("123"_b, true), tuple::make(1, 3));
        REQUIRE_THROWS_WITH_AS(ms1.advance("123"_b, true), "matching already complete", const MatchStateReuse&);

        // After assigning from a fresh value the matcher can match again.
        ms1 = re.tokenMatcher();
        CHECK_EQ(ms1.advance("123"_b, true), tuple::make(1, 3));

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
        const auto re = RegExp("123"_p, regexp::Flags({.no_sub = false}));
        const auto ms1 = re.tokenMatcher();

        CHECK_THROWS_WITH_AS(regexp::MatchState{ms1}, "cannot copy match state of regexp with sub-expressions support",
                             const InvalidArgument&);

        auto ms2 = regexp::MatchState();
        CHECK_THROWS_WITH_AS(ms2.operator=(ms1), "cannot copy match state of regexp with sub-expressions support",
                             const InvalidArgument&);
    }

    SUBCASE("copy from non-REG_STD_MATCHER regexp") {
        const auto re = RegExp("123"_p, regexp::Flags({.no_sub = true}));
        const auto ms1 = re.tokenMatcher();

        CHECK_NOTHROW(regexp::MatchState{ms1});

        auto ms2 = regexp::MatchState();
        CHECK_NOTHROW(ms2.operator=(ms1));
    }
}

TEST_CASE("caching") {
    const auto emptya = RegExp();
    const auto emptyb = RegExp();
    const auto re1a = RegExp("123"_p);
    const auto re1b = RegExp("123"_p);
    const auto re2a = RegExp({"123"_p, "456"_p}, {.no_sub = true});
    const auto re2b = RegExp({"123"_p, "456"_p}, {.no_sub = true});
    const auto re3 = RegExp("123"_p, {.no_sub = true});
    const auto re4 = RegExp({"123"_p, "456"_p}, {.no_sub = false});

    CHECK_EQ(emptya.jrx(), emptyb.jrx());
    CHECK_EQ(re1a.jrx(), re1b.jrx());
    CHECK_EQ(re2a.jrx(), re2b.jrx());
    CHECK_NE(re1a.jrx(), re3.jrx());
    CHECK_NE(re1a.jrx(), re4.jrx());
}
