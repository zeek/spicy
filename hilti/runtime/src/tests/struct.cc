// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <hilti/rt/extension-points.h>
#include <hilti/rt/logging.h>
#include <hilti/rt/types/integer.h>
#include <hilti/rt/types/null.h>
#include <hilti/rt/types/struct.h>

using namespace hilti::rt;
using namespace std::literals::string_literals;

TEST_SUITE_BEGIN("struct");

TEST_CASE("value_or_exception") {
    debug::setLocation("location:123");
    CHECK_EQ(struct_::value_or_exception(hilti::rt::Optional<int>(42)), 42);

    CHECK_THROWS_WITH_AS(struct_::value_or_exception(hilti::rt::Optional<int>(hilti::rt::Null())),
                         "struct attribute not set (location:123)", const AttributeNotSet&);
    debug::setLocation(nullptr);
}

struct Test : trait::isStruct {
    Test(int x) : _x(x), _y(x + 1) {}

    std::string __to_string() const {
        return "["s + "$_x=" + hilti::rt::to_string(_x) +
               ", "
               "$_y=" +
               hilti::rt::to_string(_y) + "]";
    }

    int _x;
    int _y;
};

struct TestWithCustomStr : public Test {
    using Test::Test;
    std::optional<std::string> __hook_to_string() { return "__hook_to_string"; }
};

TEST_CASE("to_string") { CHECK_EQ(to_string(Test(42)), "[$_x=42, $_y=43]"); }
TEST_CASE("to_string_custom") { CHECK_EQ(to_string(TestWithCustomStr(42)), "__hook_to_string"); }

TEST_SUITE_END();
