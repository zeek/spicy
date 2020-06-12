// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.
//
// @TEST-GROUP: no-jit
// @TEST-REQUIRES: using-build-directory
// @TEST-EXEC: test-util >&2
//
// Note: This is compiled through CMakeLists.txt.

#include <doctest/doctest.h>

#include <sstream>

#include <hilti/base/util.h>

TEST_SUITE_BEGIN("util");

enum class Foo { AAA, BBB, CCC };
constexpr util::enum_::Value<Foo> values[] = {
    {Foo::AAA, "aaa"},
    {Foo::BBB, "bbb"},
    {Foo::CCC, "ccc"},
};

constexpr auto from_string(const std::string_view& s) { return util::enum_::from_string<Foo>(s, values); }

TEST_CASE("enum::_from_string") {
    CHECK(from_string("aaa") == Foo::AAA);
    CHECK(from_string("ccc") == Foo::CCC);
    CHECK_THROWS_AS(from_string("xxx"), std::out_of_range); // NOLINT
}

TEST_CASE("escapeBytesForCxx") {
    CHECK(util::escapeBytesForCxx("aaa") == "aaa");
    CHECK(util::escapeBytesForCxx("\xff") == "\\377");
    CHECK(util::escapeBytesForCxx("\x02"
                                  "\x10"
                                  "\x32"
                                  "\x41"
                                  "\x15"
                                  "\x01"
                                  "\x0A") == "\\002\\0202A\\025\\001\\012");
}

TEST_SUITE_END();
