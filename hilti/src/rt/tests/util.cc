// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <locale>
#include <string>
#include <vector>

#include <hilti/rt/autogen/version.h>
#include <hilti/rt/types/integer.h>
#include <hilti/rt/types/list.h>
#include <hilti/rt/types/set.h>
#include <hilti/rt/types/time.h>
#include <hilti/rt/types/vector.h>
#include <hilti/rt/util.h>

using namespace hilti::rt;

namespace std {
ostream& operator<<(ostream& stream, const vector<string_view>& xs) {
    stream << '[';

    for ( size_t i = 0; i < xs.size(); ++i ) {
        stream << xs[i];

        if ( i != xs.size() - 1 )
            stream << ", ";
    }

    return stream << ']';
}

template<typename U, typename V>
ostream& operator<<(ostream& stream, const pair<U, V>& p) {
    return stream << "(" << p.first << ", " << p.second << ")";
}

template<typename... Ts>
ostream& operator<<(ostream& stream, const tuple<Ts...>& xs) {
    stream << "(";
    tuple_for_each(xs, [&](auto&& x) { stream << x << ", "; });
    return stream << ")";
}
} // namespace std

TEST_SUITE_BEGIN("util");

template<typename T>
T atoi_n_(const std::string_view& input, int base, unsigned num_parsed) {
    CAPTURE(input);
    CAPTURE(base);

    auto result = T();
    std::string_view::iterator it;

    try {
        it = atoi_n(input.cbegin(), input.cend(), base, &result);
    } catch ( ... ) {
        throw;
    }

    CHECK_EQ(it - input.begin(), num_parsed);
    return result;
};

TEST_CASE("atoi_n") {
    SUBCASE("parse nothing") {
        int64_t x = -42; // If nothing gets parse, this value should remain unchanged.

        SUBCASE("empty range") {
            std::string_view s = "";
            CHECK_THROWS_WITH_AS(atoi_n(s.begin(), s.end(), 10, &x), "cannot decode from empty range",
                                 const InvalidArgument&);
        }

        SUBCASE("invalid chars") {
            std::string_view s = "abc";
            auto it = atoi_n(s.begin(), s.end(), 10, &x);
            CHECK_EQ(it, s.begin());
        }

        CHECK_EQ(x, -42);
    }

    SUBCASE("parse something") {
        CHECK_THROWS_WITH_AS(atoi_n_<int>("123456", 1, 0), "base for numerical conversion must be between 2 and 36",
                             const OutOfRange&);

        CHECK_THROWS_WITH_AS(atoi_n_<int>("123456", 37, 0), "base for numerical conversion must be between 2 and 36",
                             const OutOfRange&);

        CHECK_EQ(atoi_n_<int>("123", 10, 3), 123);
        CHECK_EQ(atoi_n_<int>("00123", 10, 5), 123);
        CHECK_EQ(atoi_n_<int>("00123", 4, 5), 27);

        CHECK_EQ(atoi_n_<int>("-123", 10, 4), -123);
        CHECK_EQ(atoi_n_<int>("-00123", 10, 6), -123);
        CHECK_EQ(atoi_n_<int>("-00123", 4, 6), -27);
        CHECK_EQ(atoi_n_<int>("-00123", 3, 5), -5);
        CHECK_EQ(atoi_n_<int>("-00123", 2, 4), -1);

        CHECK_EQ(atoi_n_<int>("+123", 10, 4), 123);
        CHECK_EQ(atoi_n_<int>("+00123", 10, 6), 123);
        CHECK_EQ(atoi_n_<int>("+00123", 4, 6), 27);
        CHECK_EQ(atoi_n_<int>("+00123", 3, 5), 5);
        CHECK_EQ(atoi_n_<int>("+00123", 2, 4), 1);

        CHECK_EQ(atoi_n_<int64_t>("123ABC", 16, 6), 1194684);
        CHECK_EQ(atoi_n_<int64_t>("00123ABC", 16, 8), 1194684);
        CHECK_EQ(atoi_n_<int64_t>("-123ABC", 16, 7), -1194684);
        CHECK_EQ(atoi_n_<int64_t>("-00123ABC", 16, 9), -1194684);

        CHECK_EQ(atoi_n_<int64_t>("123Abc", 16, 6), 1194684);
        CHECK_EQ(atoi_n_<int64_t>("00123Abc", 16, 8), 1194684);
        CHECK_EQ(atoi_n_<int64_t>("-123Abc", 16, 7), -1194684);
        CHECK_EQ(atoi_n_<int64_t>("-00123Abc", 16, 9), -1194684);

        CHECK_EQ(atoi_n_<int>("-00123-123", 10, 6), -123);
        CHECK_EQ(atoi_n_<int>("-00123Z123", 10, 6), -123);
    }
}

TEST_CASE("createTemporaryFile") {
    SUBCASE("success") {
        // This test is value-parameterized over `tmp`.
        std::filesystem::path tmp;

        struct Cleanup {
            Cleanup(std::filesystem::path& tmp) : _tmp(tmp) {}
            ~Cleanup() {
                if ( std::filesystem::exists(_tmp) )
                    std::filesystem::remove(_tmp);
            }

            std::filesystem::path& _tmp;
        } _(tmp);

        SUBCASE("default prefix") { tmp = createTemporaryFile().valueOrThrow(); }

        SUBCASE("custom prefix") {
            auto prefix = "1234567890";
            tmp = createTemporaryFile(prefix).valueOrThrow();
            CHECK(startsWith(tmp.filename(), prefix));
        }

        CAPTURE(tmp);
        CHECK(std::filesystem::exists(tmp));

        const auto status = std::filesystem::status(tmp);
        CHECK_EQ(status.type(), std::filesystem::file_type::regular);
        CHECK_NE(status.permissions() & std::filesystem::perms::owner_read, std::filesystem::perms::none);
        CHECK_NE(status.permissions() & std::filesystem::perms::owner_write, std::filesystem::perms::none);
        CHECK_EQ(status.permissions() & std::filesystem::perms::owner_exec, std::filesystem::perms::none);
    }

    SUBCASE("failure") {
        CHECK(startsWith(createTemporaryFile("12/34").errorOrThrow().description(), "could not create temporary file"));
    }
}

TEST_CASE("enumerate") {
    auto input = std::vector<char>({'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'});
    for ( auto&& [i, c] : enumerate(input) ) {
        CHECK_EQ(c, input[i]);
        input[i] = ' ';
    }
    CHECK_EQ(input, std::vector<char>(input.size(), ' '));
}

TEST_CASE("escapeBytes") {
    SUBCASE("escape_quotes") {
        // This test is value-parameterized over `quote` and `escape_quotes`.
        std::string quote;
        bool escape_quotes{};
        SUBCASE("true") {
            escape_quotes = true;
            quote = "\\\"";
        }
        SUBCASE("false") {
            escape_quotes = false;
            quote = "\"";
        }

        CHECK_EQ(escapeBytes("", escape_quotes), "");
        CHECK_EQ(escapeBytes("a\"b\n12", escape_quotes), std::string("a") + quote + "b\\x0a12");
        CHECK_EQ(escapeBytes("a\"b\\n12", escape_quotes), std::string("a") + quote + "b\\\\n12");
        CHECK_EQ(escapeBytes("a\"b\\\n12", escape_quotes), std::string("a") + quote + "b\\\\\\x0a12");
        CHECK_EQ(escapeBytes("a\"b\t12", escape_quotes), std::string("a") + quote + "b\\x0912");
    }

    SUBCASE("use_octal") {
        CHECK_EQ(escapeBytes("", false, true), "");
        CHECK_EQ(escapeBytes("ab\n12", false, true), "ab\\01212");
        CHECK_EQ(escapeBytes("ab\\n12", false, true), "ab\\\\n12");
        CHECK_EQ(escapeBytes("ab\\\n12", false, true), "ab\\\\\\01212");
        CHECK_EQ(escapeBytes("ab\t12", false, true), "ab\\01112");
    }
}

TEST_CASE("escapeUTF8") {
    SUBCASE("plain") {
        CHECK_EQ(escapeUTF8(""), "");
        CHECK_EQ(escapeUTF8("abc\u1234123"), "abcሴ123");
        CHECK_EQ(escapeUTF8("abc\U00001234123"), "abcሴ123");
    }

    SUBCASE("escape_quotes") {
        CHECK_EQ(escapeUTF8("\"", false), "\"");
        CHECK_EQ(escapeUTF8("\"", true), "\\\"");
        CHECK_EQ(escapeUTF8("\"\"", false), "\"\"");
        CHECK_EQ(escapeUTF8("\"\"", true), "\\\"\\\"");
    }

    SUBCASE("escape_control") {
        CHECK_EQ(escapeUTF8(std::string(1u, '\0'), false, false), std::string(1u, '\0'));
        CHECK_EQ(escapeUTF8(std::string(1u, '\0'), false, true), "\\0");

        CHECK_EQ(escapeUTF8("\a", false, false), "\a");
        CHECK_EQ(escapeUTF8("\a", false, true), "\\a");

        CHECK_EQ(escapeUTF8("\b", false, false), "\b");
        CHECK_EQ(escapeUTF8("\b", false, true), "\\b");

        CHECK_EQ(escapeUTF8("\e", false, false), "\e");
        CHECK_EQ(escapeUTF8("\e", false, true), "\\e");

        CHECK_EQ(escapeUTF8("\f", false, false), "\f");
        CHECK_EQ(escapeUTF8("\f", false, true), "\\f");

        CHECK_EQ(escapeUTF8("\n", false, false), "\n");
        CHECK_EQ(escapeUTF8("\n", false, true), "\\n");

        CHECK_EQ(escapeUTF8("\r", false, false), "\r");
        CHECK_EQ(escapeUTF8("\r", false, true), "\\r");

        CHECK_EQ(escapeUTF8("\t", false, false), "\t");
        CHECK_EQ(escapeUTF8("\t", false, true), "\\t");

        CHECK_EQ(escapeUTF8("\v", false, false), "\v");
        CHECK_EQ(escapeUTF8("\v", false, true), "\\v");
    }

    SUBCASE("keep_hex") {
        CHECK_EQ(escapeUTF8("\x12", false, false, false), "");
        CHECK_EQ(escapeUTF8("\x12", false, false, true), "");
        CHECK_EQ(escapeUTF8("\\x12", false, false, false), "\\\\x12");
        CHECK_EQ(escapeUTF8("\\x12", false, false, true), "\\x12");
    }
}

TEST_CASE("expandEscapes") {
    CHECK_EQ(expandEscapes(""), "");
    CHECK_EQ(expandEscapes("ab\n12"), "ab\n12");
    CHECK_EQ(expandEscapes("ab\\n12"), "ab\n12");
    CHECK_THROWS_WITH_AS(expandEscapes("ab\\\n12"), "unknown escape sequence", const Exception&);
    CHECK_EQ(expandEscapes("ab\\\\n12"), "ab\\n12");
    CHECK_EQ(expandEscapes("ab\\\\\n12"), "ab\\\n12");

    CHECK_THROWS_WITH_AS(expandEscapes("\\"), "broken escape sequence", const Exception&);

    CHECK_EQ(expandEscapes("\\\""), "\"");
    CHECK_EQ(expandEscapes("\\r"), "\r");
    CHECK_EQ(expandEscapes("\\n"), "\n");
    CHECK_EQ(expandEscapes("\\t"), "\t");
    CHECK_EQ(expandEscapes("\\0"), std::string(1u, '\0'));
    CHECK_EQ(expandEscapes("\\a"), "\a");
    CHECK_EQ(expandEscapes("\\b"), "\b");
    CHECK_EQ(expandEscapes("\\v"), "\v");
    CHECK_EQ(expandEscapes("\\f"), "\f");
    CHECK_EQ(expandEscapes("\\e"), "\e");

    CHECK_THROWS_WITH_AS(expandEscapes("\\uFOO"), "incomplete unicode \\u", const Exception&);
    CHECK_THROWS_WITH_AS(expandEscapes("\\uFOOL"), "cannot decode character", const Exception&);
    CHECK_EQ(expandEscapes("\\u2614"), "☔");
    // We assume a max value of \uFFFF so the following is expanded as `\u1F60` and `E`, not `😎`.
    CHECK_EQ(expandEscapes("\\u1F60E"), "ὠE");

    CHECK_THROWS_WITH_AS(expandEscapes("\\UFOO"), "incomplete unicode \\U", const Exception&);
    CHECK_THROWS_WITH_AS(expandEscapes("\\UFOOBAR"), "incomplete unicode \\U", const Exception&);
    CHECK_THROWS_WITH_AS(expandEscapes("\\UFOOBARBAZ"), "cannot decode character", const Exception&);
    CHECK_EQ(expandEscapes("\\U00002614"), "☔");
    CHECK_EQ(expandEscapes("\\U0001F60E"), "😎");

    CHECK_THROWS_WITH_AS(expandEscapes("\\x"), "\\x used with no following hex digits", const Exception&);
    CHECK_THROWS_WITH_AS(expandEscapes("\\xZ"), "cannot decode character", const Exception&);
    CHECK_EQ(expandEscapes("\\xA"), "\xA");
    CHECK_EQ(expandEscapes("\\xAB"), "\xAB");
    CHECK_THROWS_WITH_AS(expandEscapes("\\xAZ"), "cannot decode character", const Exception&);
    CHECK_EQ(expandEscapes("\\xABC"), std::string("\xAB") + "C");
    CHECK_EQ(expandEscapes("\\x01"), "\x01");
}

TEST_CASE("isDebugVersion") {
#if HILTI_RT_BUILD_TYPE_DEBUG
    CHECK(isDebugVersion());
#else
    CHECK_FALSE(isDebugVersion());
#endif
}

TEST_CASE("join") {
    using str_list = std::initializer_list<std::string>;

    CHECK_EQ(join(str_list{}, ""), "");
    CHECK_EQ(join(str_list{"a"}, ""), "a");
    CHECK_EQ(join(str_list{"a"}, "1"), "a");
    CHECK_EQ(join(str_list{"a", "b"}, "1"), "a1b");
    CHECK_EQ(join(str_list{"a", "b", "c"}, "\b1"), "a\b1b\b1c");

    const auto null = std::string(1u, '\0');
    CHECK_EQ(join(str_list{null, null}, null), null + null + null);
}

TEST_CASE("join_tuple") {
    CHECK_EQ(join_tuple(std::make_tuple()), "");
    CHECK_EQ(join_tuple(std::make_tuple(integer::safe<uint8_t>(1), std::string("a"))), "1, \"a\"");
    CHECK_EQ(join_tuple(std::make_tuple(integer::safe<uint8_t>(1), std::string(1u, '\0'))), "1, \"\\0\"");
}

TEST_CASE("join_tuple_for_print") {
    CHECK_EQ(join_tuple_for_print(std::make_tuple()), "");
    CHECK_EQ(join_tuple_for_print(std::make_tuple(integer::safe<uint8_t>(1), std::string("a"))), "1, a");
    const auto null = std::string(1u, '\0');
    CHECK_EQ(join_tuple_for_print(std::make_tuple(integer::safe<uint8_t>(1), null)), "1, " + null);
}

TEST_CASE("ltrim") {
    CHECK_EQ(ltrim("", ""), "");
    CHECK_EQ(ltrim("", "abc"), "");
    CHECK_EQ(ltrim("a1b2c3d4", "abc"), "1b2c3d4");
    CHECK_EQ(ltrim("ab1b2c3d4", "abc"), "1b2c3d4");
    CHECK_EQ(ltrim("abc1b2c3d4", "abc"), "1b2c3d4");

    const auto null = std::string(1u, '\0');
    CHECK_EQ(ltrim(null + null + "abc", "a" + null), "bc");
}

TEST_CASE("map_tuple") {
    CHECK_EQ(map_tuple(std::make_tuple(), []() {}), std::make_tuple());
    CHECK_EQ(map_tuple(std::make_tuple(), []() { return 0; }), std::make_tuple());
    CHECK_EQ(map_tuple(std::make_tuple(), [](auto&&) {}), std::make_tuple());
    CHECK_EQ(map_tuple(std::make_tuple(), [](const auto&) {}), std::make_tuple());
    CHECK_EQ(map_tuple(std::make_tuple(), [](auto&) {}), std::make_tuple());
    CHECK_EQ(map_tuple(std::make_tuple(), [](auto&&) { return 0; }), std::make_tuple());
    CHECK_EQ(map_tuple(std::make_tuple(), [](auto&& x) { return decltype(x){}; }), std::make_tuple());
    CHECK_EQ(map_tuple(std::make_tuple(1u, 1L, std::string("a")), [](auto&& x) { return decltype(x){}; }),
             std::make_tuple(0u, 0L, std::string()));
    CHECK_EQ(map_tuple(std::make_tuple(1u, 1L, std::string("a")), [](auto&& x) { return std::move(x); }),
             std::make_tuple(1u, 1L, std::string("a")));

    auto input = std::make_tuple(1u, 1L, std::string("a"));
    CHECK_EQ(map_tuple(input,
                       [](auto& x) {
                           auto y = x;
                           x += x;
                           return y;
                       }),
             std::make_tuple(1u, 1L, std::string("a")));
    CHECK_EQ(input, std::make_tuple(2u, 2L, std::string("aa")));
}

TEST_CASE("memory_statistics") {
    auto ms = memory_statistics();

    CHECK_GT(ms.memory_heap, 0);

    // Fiber statistics are only available if some fibers were executed.
    // TODO(bbannier): Execute a fiber in this test so below branch is always taken.
    if ( ms.max_fibers > 0 ) {
        CHECK_GT(ms.num_fibers, 0);
        CHECK_LE(ms.num_fibers, ms.max_fibers);

        CHECK_GT(ms.cached_fibers, 0);
        CHECK_LE(ms.cached_fibers, ms.max_fibers);
        CHECK_GE(ms.cached_fibers, ms.num_fibers);
    }
}

TEST_CASE("pow") {
    using hilti::rt::pow;
    CHECK_EQ(pow(1, 0), 1);
    CHECK_EQ(pow(1, 1), 1);

    CHECK_EQ(pow(-1, 0), 1);
    CHECK_EQ(pow(-1, 1), -1);
    CHECK_EQ(pow(-1, 2), 1);
    CHECK_EQ(pow(-1, 3), -1);

    CHECK_EQ(pow(2, 0), 1);
    CHECK_EQ(pow(2, 0), 1);
    CHECK_EQ(pow(2, 1), 2);
    CHECK_EQ(pow(2, 2), 4);
    CHECK_EQ(pow(2, 4), 16);
    CHECK_EQ(pow(2, 5), 32);
    CHECK_EQ(pow(2, 16), 65536);

    CHECK_EQ(pow(integer::safe<int8_t>(2), 3), 8);
    CHECK_THROWS_WITH_AS(pow(integer::safe<int8_t>(2), 4), "integer overflow", const Overflow&);
    CHECK_EQ(pow(integer::safe<int16_t>(2), 4), 16);
    CHECK_EQ(pow(integer::safe<int16_t>(2), integer::safe<int16_t>(4)), 16);
}

TEST_CASE("normalizePath") {
    CHECK_EQ(normalizePath(""), "");

    const auto does_not_exist1 = "/does/not/exist";
    const auto does_not_exist2 = "does/not/exist";
    const auto does_not_exist3 = "./does//not///exist";
    REQUIRE_FALSE(std::filesystem::exists(does_not_exist1));
    REQUIRE_FALSE(std::filesystem::exists(does_not_exist2));
    REQUIRE_FALSE(std::filesystem::exists(does_not_exist3));
    CHECK_EQ(normalizePath(does_not_exist1), does_not_exist1);
    CHECK_EQ(normalizePath(does_not_exist2), does_not_exist2);

    // TODO(bbannier): actually normalize non-existing paths,
    // e.g., remove double slashes, normalize `a/../b/` to `b/
    // and similar. This test needs to be updated in that case.
    CHECK_EQ(normalizePath(does_not_exist3), does_not_exist3);

    REQUIRE(std::filesystem::exists("/dev/null"));
    CHECK_EQ(normalizePath("/dev/null"), "/dev/null");
    CHECK_EQ(normalizePath("/dev//null"), "/dev/null");
    CHECK_EQ(normalizePath("/dev///null"), "/dev/null");
    CHECK_EQ(normalizePath("/dev/.//null"), "/dev/null");

    const auto cwd = std::filesystem::current_path();
    REQUIRE(std::filesystem::exists(cwd));
    CHECK_EQ(normalizePath(cwd / ".."), cwd.parent_path());
    CHECK_EQ(normalizePath(cwd / ".." / ".."), cwd.parent_path().parent_path());
}

TEST_CASE("replace") {
    CHECK_EQ(replace("abcabc", "b", " "), "a ca c");
    CHECK_EQ(replace("abcabc", "1", " "), "abcabc");
    CHECK_EQ(replace("abcabc", "b", ""), "acac");
    CHECK_EQ(replace("abcabc", "", "b"), "abcabc");
    CHECK_EQ(replace("", "a", "b"), "");
}

TEST_CASE("rtrim") {
    CHECK_EQ(rtrim("", ""), "");
    CHECK_EQ(rtrim("", "abc"), "");
    CHECK_EQ(rtrim("4d3c2b1a", "abc"), "4d3c2b1");
    CHECK_EQ(rtrim("4d3c2b1ba", "abc"), "4d3c2b1");
    CHECK_EQ(rtrim("4d3c2b1cba", "abc"), "4d3c2b1");

    const auto null = std::string(1u, '\0');
    CHECK_EQ(rtrim("cba" + null + null, "a" + null), "cb");
}

TEST_CASE("rsplit1") {
    auto str_pair = std::make_pair<std::string, std::string>;

    SUBCASE("w/ delim") {
        CHECK_EQ(rsplit1("", ""), str_pair("", ""));
        CHECK_EQ(rsplit1(" a", " "), str_pair("", "a"));
        CHECK_EQ(rsplit1(" a b", " "), str_pair(" a", "b"));
        CHECK_EQ(rsplit1("a  b", " "), str_pair("a ", "b"));
        CHECK_EQ(rsplit1("a   b", " "), str_pair("a  ", "b"));
        CHECK_EQ(rsplit1("a b c", " "), str_pair("a b", "c"));
        CHECK_EQ(rsplit1("a b c ", " "), str_pair("a b c", ""));
        CHECK_EQ(rsplit1("abc", " "), str_pair("", "abc"));
    }

    SUBCASE("w/o delim") {
        CHECK_EQ(rsplit1(""), str_pair("", ""));
        CHECK_EQ(rsplit1("\ta"), str_pair("", "a"));
        CHECK_EQ(rsplit1("\ta\vb"), str_pair("\ta", "b"));
        CHECK_EQ(rsplit1("a  b"), str_pair("a ", "b"));
        CHECK_EQ(rsplit1("a   b"), str_pair("a  ", "b"));
        CHECK_EQ(rsplit1("a b c"), str_pair("a b", "c"));
        CHECK_EQ(rsplit1("a b c "), str_pair("a b c", ""));
        CHECK_EQ(rsplit1("abc"), str_pair("", "abc"));
    }
}

TEST_CASE("split") {
    using str_vec = std::vector<std::string_view>;

    SUBCASE("w/ delim") {
        CHECK_EQ(split("a:b:c", ""), str_vec({"a:b:c"}));
        CHECK_EQ(split("", ""), str_vec({""}));
        CHECK_EQ(split("a:b:c", ":"), str_vec({"a", "b", "c"}));
        CHECK_EQ(split("a:b::c", ":"), str_vec({"a", "b", "", "c"}));
        CHECK_EQ(split("a:b:::c", ":"), str_vec({"a", "b", "", "", "c"}));
        CHECK_EQ(split(":a:b:c", ":"), str_vec({"", "a", "b", "c"}));
        CHECK_EQ(split("::a:b:c", ":"), str_vec({"", "", "a", "b", "c"}));
        CHECK_EQ(split("a:b:c:", ":"), str_vec({"a", "b", "c", ""}));
        CHECK_EQ(split("a:b:c::", ":"), str_vec({"a", "b", "c", "", ""}));
        CHECK_EQ(split("", ":"), str_vec({""}));

        CHECK_EQ(split("12345", "1"), std::vector<std::string_view>({"", "2345"}));
        CHECK_EQ(split("12345", "23"), std::vector<std::string_view>({"1", "45"}));
        CHECK_EQ(split("12345", "a"), std::vector<std::string_view>({"12345"}));
        CHECK_EQ(split("12345", ""), std::vector<std::string_view>({"12345"}));
    }

    SUBCASE("w/o delim") {
        CHECK_EQ(split("a b c"), str_vec({"a", "b", "c"}));
        CHECK_EQ(split("a\t b c"), str_vec({"a", "b", "c"}));
        CHECK_EQ(split("a    b       c"), str_vec({"a", "b", "c"}));
        CHECK_EQ(split("   a    b \t \n c"), str_vec({"a", "b", "c"}));
        CHECK_EQ(split("\n   a    b       c\t "), str_vec({"a", "b", "c"}));
        CHECK_EQ(split(""), str_vec{});
        CHECK_EQ(split("\t\v\n\r"), str_vec{});
        CHECK_EQ(split(" \n "), str_vec{});
    }
}

TEST_CASE("split1") {
    auto str_pair = std::make_pair<std::string, std::string>;

    SUBCASE("w/ delim") {
        CHECK_EQ(split1("", " "), str_pair("", ""));
        CHECK_EQ(split1(" a", " "), str_pair("", "a"));
        CHECK_EQ(split1(" a b", " "), str_pair("", "a b"));
        CHECK_EQ(split1("a  b", " "), str_pair("a", " b"));
        CHECK_EQ(split1("a   b", " "), str_pair("a", "  b"));
        CHECK_EQ(split1("a b c", " "), str_pair("a", "b c"));
    }

    SUBCASE("w/o delim") {
        CHECK_EQ(split1(""), str_pair("", ""));
        CHECK_EQ(split1("\ta"), str_pair("", "a"));
        CHECK_EQ(split1("\ta b"), str_pair("", "a b"));
        CHECK_EQ(split1("a  b"), str_pair("a", "b"));
        CHECK_EQ(split1("a   b"), str_pair("a", "b"));
        CHECK_EQ(split1("a b c"), str_pair("a", "b c"));
    }
}

TEST_CASE("startsWith") {
    CHECK(startsWith("", ""));
    CHECK_FALSE(startsWith("", "a"));
    CHECK(startsWith("abc", "a"));
    CHECK_FALSE(startsWith("abc", "a1"));
    CHECK(startsWith("abc", "ab"));
    CHECK(startsWith("abc", "abc"));

    const auto null = std::string(1u, '\0');

    CHECK(startsWith(null + "abc", null));
    CHECK(startsWith(null + "abc", null + "a"));
    CHECK_FALSE(startsWith(null + "abc", "abc"));
}

TEST_CASE("strftime") {
    REQUIRE_EQ(::setenv("TZ", "UTC", 1), 0);
    std::locale::global(std::locale::classic());

    CHECK_EQ(strftime("%A %c", Time()), "Thursday Thu Jan  1 00:00:00 1970");

    CHECK_THROWS_WITH_AS(strftime("", Time()), "could not format timestamp", const InvalidArgument&);
    CHECK_THROWS_WITH_AS(strftime("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
                                  "XXXXXXXXXXXXXXXX %A %c",
                                  Time()),
                         "could not format timestamp", const InvalidArgument&);
}

TEST_CASE("systemByteOrder") {
#ifdef LITTLE_ENDIAN
    CHECK_EQ(systemByteOrder(), ByteOrder::Little);
#elif BIG_ENDIAN
    CHECK_EQ(systemByteOrder(), ByteOrder::Big);
#endif
}

TEST_CASE("transform") {
    SUBCASE("list") {
        CHECK_EQ(transform(std::list<int>(), [](auto&& x) { return x + x; }), std::vector<int>());
        CHECK_EQ(transform(std::list({1, 2, 3}), [](auto&& x) { return x + x; }), std::vector({2, 4, 6}));
    }

    SUBCASE("set") {
        CHECK_EQ(transform(std::set<int>(), [](auto&& x) { return x + x; }), std::set<int>());
        CHECK_EQ(transform(std::set({1, 2, 3}), [](auto&& x) { return x + x; }), std::set({2, 4, 6}));
    }

    SUBCASE("List") {
        CHECK_EQ(transform(List<int>(), [](auto&& x) { return x + x; }), List<int>());
        CHECK_EQ(transform(List({1, 2, 3}), [](auto&& x) { return x + x; }), List({2, 4, 6}));
    }

    SUBCASE("Set") {
        CHECK_EQ(transform(Set<int>(), [](auto&& x) { return x + x; }), Set<int>());
        CHECK_EQ(transform(Set({1, 2, 3}), [](auto&& x) { return x + x; }), Set({2, 4, 6}));
    }

    SUBCASE("Vector") {
        CHECK_EQ(transform(Vector<int>(), [](auto&& x) { return x + x; }), Vector<int>());
        CHECK_EQ(transform(Vector({1, 2, 3}), [](auto&& x) { return x + x; }), Vector({2, 4, 6}));
    }
}

TEST_CASE("trim") {
    CHECK_EQ(trim("", ""), "");
    CHECK_EQ(trim("aa123a", ""), "aa123a");
    CHECK_EQ(trim("aa123a", "abc"), "123");
    CHECK_EQ(trim("aa123a", "XYZ"), "aa123a");

    const auto null = std::string(1u, '\0');
    CHECK_EQ(trim(null + null + "123" + null + "abc" + null, null), "123" + null + "abc");
}

TEST_CASE("tuple_for_each") {
    tuple_for_each(std::make_tuple(), []() {});
    tuple_for_each(std::make_tuple(), [](auto&) {});
    tuple_for_each(std::make_tuple(), [](const auto&) {});
    tuple_for_each(std::make_tuple(), [](auto&&) {});

    tuple_for_each(std::make_tuple(1, ""), [](auto&) {});
    tuple_for_each(std::make_tuple(1, ""), [](const auto&) {});
    tuple_for_each(std::make_tuple(1, ""), [](auto&&) {});

    tuple_for_each(std::make_tuple(1, ""), [](auto& x) { return x; });
    tuple_for_each(std::make_tuple(1, ""), [](const auto& x) { return x; });
    tuple_for_each(std::make_tuple(1, ""), [](auto&& x) { return x; });

    {
        auto input = std::make_tuple();
        std::stringstream ss;
        tuple_for_each(input, [&](auto&& x) { ss << x; });
        CHECK_EQ(ss.str(), "");
    }

    {
        auto input = std::make_tuple(1u, 2L, std::string("a"));
        std::stringstream ss;
        tuple_for_each(input, [&](auto&& x) { ss << x; });
        CHECK_EQ(ss.str(), "12a");
    }
}

TEST_CASE("version") {
    CHECK_MESSAGE(version().find("HILTI runtime library") != std::string::npos,
                  fmt("version string '%s' does not contain 'HILTI runtime library'", version()));

    CHECK_MESSAGE(version().find(PROJECT_VERSION_STRING_LONG) != std::string::npos,
                  fmt("version string '%s' does not contain version '%s'", version(), PROJECT_VERSION_STRING_LONG));

    const std::string build_type = isDebugVersion() ? "debug build" : "release build";
    CHECK_MESSAGE(version().find(build_type) != std::string::npos,
                  fmt("version string '%s' does not contain build type '%s'", version(), build_type));
}

TEST_SUITE_END();
