// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#include <optional>

#include <hilti/rt/doctest.h>
#include <hilti/rt/types/null.h>
#include <hilti/rt/types/optional.h>

using namespace hilti::rt;

TEST_SUITE_BEGIN("optional");

TEST_CASE("value") {
    SUBCASE("rvalue") {
        CHECK_THROWS_WITH_AS(optional::value(std::optional<int>(), "foo.spicy"), "unset optional value (foo.spicy)",
                             const UnsetOptional&);

        CHECK_EQ(optional::value(std::optional<int>(0), "foo.spicy"), 0);
    }

    SUBCASE("lvalue") {
        auto o = std::optional<int>();

        CHECK_THROWS_WITH_AS(optional::value(o, "foo.spicy"), "unset optional value (foo.spicy)", const UnsetOptional&);

        o = 0;
        auto& v = optional::value(o, "foo.spicy");
        CHECK_EQ(v, 0);

        v += 42;
        CHECK_EQ(*o, 42);
    }
}

TEST_CASE("valueOrInit") {
    SUBCASE("explicit default") {
        auto o = std::optional<int8_t>();
        CHECK_EQ(optional::valueOrInit(o, int8_t(47)), 47);
        CHECK_EQ(*o, 47);
    }

    SUBCASE("implicit default") {
        auto o = std::optional<int8_t>();
        CHECK_EQ(optional::valueOrInit(o), 0);
        CHECK_EQ(*o, 0);
    }
}

TEST_CASE("tryValue") {
    CHECK_THROWS_WITH_AS(optional::tryValue(std::optional<int8_t>()), "std::exception", const optional::Unset&);
    CHECK_EQ(optional::tryValue(std::optional<int8_t>(42)), 42);
}

std::optional<std::string> foo(std::optional<std::string> s) { return s; }

TEST_CASE("null") {
    std::optional<int8_t> x;
    x = hilti::rt::Null();
    CHECK(! x.has_value());
    CHECK(! foo(hilti::rt::Null()).has_value());
}

TEST_SUITE_END();
