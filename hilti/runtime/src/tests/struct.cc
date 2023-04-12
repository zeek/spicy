// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <optional>

#include <hilti/rt/doctest.h>
#include <hilti/rt/extension-points.h>
#include <hilti/rt/types/integer.h>
#include <hilti/rt/types/struct.h>
#include <hilti/rt/logging.h>

using namespace hilti::rt;

TEST_SUITE_BEGIN("struct");

TEST_CASE("value_or_exception") {
    debug::setLocation("location:123");
    CHECK_EQ(struct_::value_or_exception(std::optional<int>(42)), 42);

    CHECK_THROWS_WITH_AS(struct_::value_or_exception(std::optional<int>(std::nullopt)),
                         "struct attribute not set (location:123)", const AttributeNotSet&);
    debug::setLocation(nullptr);
}

struct Test : trait::isStruct {
    Test(int x) : _x(x), _y(x + 1) {}

    template<typename F>
    void __visit(F f) const {
        f("_x", _x);
        f("_y", _y);
    }

    int _x;
    int _y;
};

struct TestWithCustomStr : public Test {
    using Test::Test;
    std::optional<std::string> __str__() { return "__str__"; }
};

TEST_CASE("to_string") { CHECK_EQ(to_string(Test(42)), "[$_x=42, $_y=43]"); }
TEST_CASE("to_string_custom") { CHECK_EQ(to_string(TestWithCustomStr(42)), "__str__"); }

TEST_SUITE_END();
