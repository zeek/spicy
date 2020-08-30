// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <optional>

#include <hilti/rt/doctest.h>
#include <hilti/rt/extension-points.h>
#include <hilti/rt/types/integer.h>
#include <hilti/rt/types/struct.h>

using namespace hilti::rt;

TEST_SUITE_BEGIN("struct");

TEST_CASE("value_or_exception") {
    CHECK_EQ(struct_::value_or_exception(std::optional<int>(42), "location:123"), 42);

    CHECK_THROWS_WITH_AS(struct_::value_or_exception(std::optional<int>(std::nullopt), "location:123"),
                         "struct attribute not set (location:123)", const AttributeNotSet&);
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

TEST_CASE("to_string") { CHECK_EQ(to_string(Test(42)), "[$_x=42, $_y=43]"); }

TEST_SUITE_END();
