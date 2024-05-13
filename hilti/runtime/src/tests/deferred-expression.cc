// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <cstddef>
#include <type_traits>

#include <hilti/rt/deferred-expression.h>
#include <hilti/rt/doctest.h>
#include <hilti/rt/types/integer.h>

using namespace hilti::rt;

TEST_SUITE_BEGIN("DeferredExpression");

TEST_CASE("assign") {
    int i = 0;
    auto expr = DeferredExpression<int32_t>([&]() { return ++i; });
    REQUIRE_EQ(i, 0);

    CHECK_EQ(expr(), 1);
    CHECK_EQ(i, 1);

    SUBCASE("rvalue") {
        expr = DeferredExpression<int32_t>([]() { return 0; });
        CHECK_EQ(expr(), 0);
        CHECK_EQ(i, 1); // Not incrementing anymore.
    }

    SUBCASE("lvalue") {
        const auto expr2 = DeferredExpression<int32_t>([]() { return 0; });
        expr = expr2;
        CHECK_EQ(expr(), 0);
        CHECK_EQ(i, 1); // Not incrementing anymore.
    }
}

TEST_CASE("construct") {
    int i = 0;
    auto expr = DeferredExpression<int>([&i]() { return ++i; });

    SUBCASE("default") {
        // Construction does not evaluate passed function.
        CHECK_EQ(i, 0);
    }

    SUBCASE("copy") {
        auto expr2 = DeferredExpression(expr);
        // Copy construction does not evaluate passed function.
        CHECK_EQ(i, 0);

        // Copies share any data dependencies of original function.
        REQUIRE_EQ(expr(), 1);
        CHECK_EQ(i, 1);

        REQUIRE_EQ(expr2(), 2);
        CHECK_EQ(i, 2);
    }

    SUBCASE("move") {
        auto expr2 = DeferredExpression(std::move(expr));
        // Move construction does not evaluate passed function.
        CHECK_EQ(i, 0);

        REQUIRE_EQ(expr2(), 1);
        CHECK_EQ(i, 1);
    }
}

TEST_CASE("evaluate") {
    int i = 0;
    auto expr = DeferredExpression<int>([&i]() { return ++i; });

    CHECK_EQ(expr(), 1);
    CHECK_EQ(expr(), 2);
}

TEST_CASE("fmt") {
    int i = 0;
    auto expr = DeferredExpression<int>([&i]() { return ++i; });

    // Stringification evaluates the expression.
    CHECK_EQ(fmt("%s", expr), "1");
    CHECK_EQ(fmt("%s", expr), "2");
}

TEST_CASE("to_string") {
    int i = 0;
    auto expr = DeferredExpression<int>([&i]() { return ++i; });

    // Stringification evaluates the expression.
    CHECK_EQ(to_string(expr), "1");
    CHECK_EQ(to_string(expr), "2");
}

TEST_CASE("to_string_for_print") {
    int i = 0;
    auto expr = DeferredExpression<Bytes>([&i]() { return Bytes(fmt("\\x0%d", ++i)); });

    // Stringification evaluates the expression.
    CHECK_EQ(to_string_for_print(expr), R"#(\\x01)#");
    CHECK_EQ(to_string_for_print(expr), R"#(\\x02)#");
}

TEST_SUITE_END();
