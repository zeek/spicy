// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <optional>

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
        CHECK_EQ(o, 42);
    }
}

TEST_SUITE_END();
