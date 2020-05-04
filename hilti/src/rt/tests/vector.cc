// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <hilti/rt/types/vector.h>

using namespace hilti::rt;

TEST_SUITE_BEGIN("Vector");

TEST_CASE("front") {
    Vector<int> xs;
    CHECK_THROWS_AS(xs.front(), const IndexError&);
    CHECK_THROWS_WITH_AS(xs.front(), "vector is empty", const IndexError&);

    xs.push_back(1);
    CHECK_EQ(xs.front(), 1);
    CHECK_EQ(xs.size(), 1u);
}

TEST_CASE("back") {
    Vector<int> xs;
    CHECK_THROWS_WITH_AS(xs.back(), "vector is empty", const IndexError&);

    xs.push_back(1);
    CHECK_EQ(xs.back(), 1);
    CHECK_EQ(xs.size(), 1u);
}

TEST_CASE("concat") {
    Vector<int> x({1});
    auto xs = x + x;

    CHECK_EQ(xs.size(), 2);
    CHECK_EQ(xs[0], 1);
    CHECK_EQ(xs[1], 1);
}

TEST_CASE("subscript") {
    CHECK_THROWS_WITH_AS(Vector<int>()[47], "vector index 47 out of range", const IndexError&);

    Vector<int> xs;
    REQUIRE_EQ(xs.size(), 0u);
    CHECK_EQ(xs[3], int());
    CHECK_EQ(xs.size(), 4u);

    const auto ys = xs;
    CHECK_THROWS_WITH_AS(ys[47], "vector index 47 out of range", const IndexError&);
}

TEST_SUITE_END();
