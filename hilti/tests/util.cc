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

enum class Foo { AAA, BBB, CCC };

constexpr util::enum_::Value<Foo> values[] = {
    {Foo::AAA, "aaa"},
    {Foo::BBB, "bbb"},
    {Foo::CCC, "ccc"},
};

constexpr auto from_string(const std::string_view& s) { return util::enum_::from_string<Foo>(s, values); }
constexpr auto to_string(Foo f) { return util::enum_::to_string(f, values); }

TEST_CASE("enum string conversion") {
    CHECK(from_string("aaa") == Foo::AAA);
    CHECK(from_string("ccc") == Foo::CCC);
    CHECK_THROWS_AS(from_string("xxx"), std::out_of_range); // NOLINT
}
