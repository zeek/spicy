// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <hilti/rt/types/vector.h>

using namespace hilti::rt;

TEST_CASE("Vector") {
    SUBCASE("front") {
        Vector<int> xs;
        CHECK_THROWS_AS(xs.front(), const IndexError&);
        CHECK_THROWS_WITH_AS(xs.front(), "vector is empty", const IndexError&);

        xs.push_back(1);
        CHECK_EQ(xs.front(), 1);
        CHECK_EQ(xs.size(), 1u);
    }

    SUBCASE("back") {
        Vector<int> xs;
        CHECK_THROWS_WITH_AS(xs.back(), "vector is empty", const IndexError&);

        xs.push_back(1);
        CHECK_EQ(xs.back(), 1);
        CHECK_EQ(xs.size(), 1u);
    }

    SUBCASE("concat") {
        Vector<int> x({1});
        auto xs = x + x;

        CHECK_EQ(xs.size(), 2);
        CHECK_EQ(xs[0], 1);
        CHECK_EQ(xs[1], 1);
    }
}
