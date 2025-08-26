// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.
//
// @TEST-REQUIRES: using-build-directory
// @TEST-EXEC: test-util >&2
//
// Note: This is compiled through CMakeLists.txt.

#include <doctest/doctest.h>

#include <cstdlib>
#include <vector>

#include <hilti/rt/filesystem.h>

#include <hilti/autogen/config.h>
#include <hilti/base/util.h>

TEST_SUITE_BEGIN("util");

enum class Foo { AAA, BBB, CCC };
constexpr hilti::util::enum_::Value<Foo> Values[] = {
    {.value = Foo::AAA, .name = "aaa"},
    {.value = Foo::BBB, .name = "bbb"},
    {.value = Foo::CCC, .name = "ccc"},
};

constexpr static auto from_string(std::string_view s) { return hilti::util::enum_::from_string<Foo>(s, Values); }

TEST_SUITE_BEGIN("util");

TEST_CASE("enum::_from_string") {
    CHECK(from_string("aaa") == Foo::AAA);
    CHECK(from_string("ccc") == Foo::CCC);
    CHECK_THROWS_AS(from_string("xxx"), std::out_of_range); // NOLINT
}

TEST_CASE("escapeBytesForCxx") {
    CHECK(hilti::util::escapeBytesForCxx("aaa") == "aaa");
    CHECK(hilti::util::escapeBytesForCxx("\xff") == "\\377");
    CHECK(hilti::util::escapeBytesForCxx("\x02"
                                         "\x10"
                                         "\x32"
                                         "\x41"
                                         "\x15"
                                         "\x01"
                                         "\x0A") == "\\002\\0202A\\025\\001\\012");
}

TEST_CASE("cacheDirectory") {
    hilti::Configuration configuration;
    configuration.build_directory = "BUILD";
    configuration.version_string = "0.1.2";
    ::setenv("HOME", "HOME", 1);

    SUBCASE("use build") {
        configuration.uses_build_directory = true;

        // If the build directory is used, neither the home directory nor an
        // environment-specified `SPICY_CACHE` are taken into account.

        SUBCASE("env override") { ::setenv("SPICY_CACHE", "OVERRIDE", 1); }
        SUBCASE("no env override") { ::unsetenv("SPICY_CACHE"); }

        CHECK_EQ(hilti::util::cacheDirectory(configuration), hilti::rt::filesystem::path("BUILD") / "cache" / "spicy");
    }

    SUBCASE("use install") {
        configuration.uses_build_directory = false;

        // If no build directory is used the cache directory is either in the
        // HOME directory or taken from the environment variable `SPICY_CACHE`.
        // The environment variable has higher precedence.

        auto cache = hilti::rt::filesystem::path("HOME") / ".cache" / "spicy" / configuration.version_string;

        SUBCASE("env override") {
            ::setenv("SPICY_CACHE", "OVERRIDE", 1);
            cache = hilti::rt::filesystem::path("OVERRIDE");
        }
        SUBCASE("no env override") { ::unsetenv("SPICY_CACHE"); }

        CHECK_EQ(hilti::util::cacheDirectory(configuration), cache);
    }
}

TEST_CASE("removeDuplicates") {
    CHECK_EQ(hilti::util::removeDuplicates(std::vector<int>{}), std::vector<int>{});
    CHECK_EQ(hilti::util::removeDuplicates(std::vector<int>{4, 3, 2, 1}), std::vector<int>{4, 3, 2, 1});
    CHECK_EQ(hilti::util::removeDuplicates(std::vector<int>{7, 8, 3, 8, 3, 5, 0, 7}), std::vector<int>{7, 8, 3, 5, 0});
}

TEST_CASE("split_shell_unsafe") {
    CHECK_EQ(hilti::util::splitShellUnsafe(R"()"), std::vector<std::string>{});
    CHECK_EQ(hilti::util::splitShellUnsafe(R"(1)"), std::vector<std::string>{"1"});
    CHECK_EQ(hilti::util::splitShellUnsafe(R"(1 2 3)"), std::vector<std::string>{"1", "2", "3"});
    CHECK_EQ(hilti::util::splitShellUnsafe(R"('1 2 3')"), std::vector<std::string>{"1 2 3"});
    CHECK_EQ(hilti::util::splitShellUnsafe(R"('1 2' 3)"), std::vector<std::string>{"1 2", "3"});
    CHECK_EQ(hilti::util::splitShellUnsafe(R"("1 2" 3)"), std::vector<std::string>{"1 2", "3"});
    CHECK_EQ(hilti::util::splitShellUnsafe(R"("\"1" 2\" 3)"), std::vector<std::string>{R"("1)", R"(2")", "3"});
    CHECK_EQ(hilti::util::splitShellUnsafe(R"(\\"1 2\\" 3)"), std::vector<std::string>{R"(\1 2\)", "3"});

    // Command substitutions are supported.
    CHECK_EQ(hilti::util::splitShellUnsafe(R"(1 `true`)"), std::vector<std::string>{R"(1)"});

    auto from_unset_var = hilti::util::splitShellUnsafe(R"($SHELL_VARIABLE_WHICH_IS_EXTREMELY_LIKELY_TO_BE_UNDEFINED)");
    auto is_unset_or_empty = ! from_unset_var.hasValue() || from_unset_var->empty();
    CHECK(is_unset_or_empty);
}

TEST_SUITE_END();
