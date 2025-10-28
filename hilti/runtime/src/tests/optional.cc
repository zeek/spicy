// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <hilti/rt/logging.h>
#include <hilti/rt/types/null.h>
#include <hilti/rt/types/optional.h>

using namespace hilti::rt;

TEST_SUITE_BEGIN("optional");

TEST_CASE("value") {
    SUBCASE("rvalue") {
        debug::setLocation("foo.spicy");
        CHECK_THROWS_WITH_AS(Optional<int>().value(), "unset optional value (foo.spicy)", const UnsetOptional&);

        CHECK_EQ(Optional<int>(0).value(), 0);
        debug::setLocation(nullptr);
    }

    SUBCASE("lvalue") {
        debug::setLocation("foo.spicy");
        auto o = Optional<int>();

        CHECK_THROWS_WITH_AS(o.value(), "unset optional value (foo.spicy)", const UnsetOptional&);

        o = 0;
        auto& v = o.value();
        CHECK_EQ(v, 0);

        v += 42;
        CHECK_EQ(*o, 42);
        debug::setLocation(nullptr);
    }
}

TEST_CASE("valueOrInit") {
    SUBCASE("explicit default") {
        auto o = Optional<int8_t>();
        CHECK_EQ(o.valueOrInit(int8_t(47)), 47);
        CHECK_EQ(*o, 47);
    }

    SUBCASE("implicit default") {
        auto o = Optional<int8_t>();
        CHECK_EQ(o.valueOrInit(), 0);
        CHECK_EQ(*o, 0);
    }
}

TEST_CASE("tryValue") {
    CHECK_THROWS_WITH_AS(Optional<int8_t>().tryValue(), "std::exception", const optional::Unset&);
    CHECK_EQ(Optional<int8_t>(42).tryValue(), 42);
}

Optional<std::string> foo(Optional<std::string> s) { return s; }

TEST_CASE("null") {
    Optional<int8_t> x;
    x = hilti::rt::Null();
    CHECK(! x.hasValue());
    CHECK(! foo(hilti::rt::Null()).hasValue());
}

TEST_SUITE_END();
