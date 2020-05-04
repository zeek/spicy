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
    // Size check in subscript access is only performed eagerly if the
    // access yields an rvalue. If it yields an lvalue the check is
    // performed lazily and only at the point where the value is accessed.

    SUBCASE("lvalue-semantics") {
        Vector<int> xs;

        // No size check since no access to yielded value.
        CHECK_NOTHROW(xs[47]);

        // Access to the yielded value triggers a size check.
        CHECK_THROWS_WITH_AS((void)int(xs[47]), "vector index 47 out of range", const IndexError&);

        // Assigning to the yielded value potentially resizes the vector.
        xs[47] = 11;
        CHECK_EQ(xs.size(), 47 + 1); // Vector resized.
        CHECK_EQ(xs[12], int());     // Added elements default-initialzed.
        CHECK_EQ(xs[47], 11);        // Assignment is to added value.
    }

    SUBCASE("rvalue-semantics") {
        const Vector<int> xs;
        CHECK_THROWS_WITH_AS(xs[47], "vector index 47 out of range", const IndexError&);
        CHECK_THROWS_WITH_AS(Vector<int>()[47], "vector index 47 out of range", const IndexError&);
    }
}

TEST_SUITE_END();
