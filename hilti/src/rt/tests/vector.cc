// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <hilti/rt/types/integer.h>
#include <hilti/rt/types/vector.h>
#include <memory>

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

    const Vector<int> zs({0, 1, 2, 3, 4, 5});
    CHECK_EQ(zs[5], 5);

    CHECK_EQ(Vector<int>({0, 1, 2, 3, 4, 5})[5], 5);
}

TEST_CASE("safe_begin") {
    SUBCASE("element removed") {
        Vector<int> xs({1});
        auto it = safe_begin(xs);
        CHECK_EQ(*it, 1);
        xs.pop_back();
        CHECK_THROWS_WITH_AS(*it, "index 0 out of bounds", const InvalidIterator&);
    }

    SUBCASE("container removed") {
        auto it = []() {
            Vector<int> xs({1});
            return safe_begin(xs);
        }();
        CHECK_THROWS_WITH_AS(*it, "bound object has expired", const InvalidIterator&);
    }

    SUBCASE("container removed (const)") {
        auto it = []() {
            const Vector<int> xs({1});
            return safe_begin(xs);
        }();
        CHECK_THROWS_WITH_AS(*it, "bound object has expired", const InvalidIterator&);
    }
}

TEST_CASE("assign") {
    SUBCASE("lvalue") {
        Vector<int> xs;
        xs = Vector<int>({1, 2, 3});
        CHECK_EQ(xs, Vector<int>({1, 2, 3}));
    }

    SUBCASE("rvalue") {
        Vector<int> xs;
        Vector<int> ys({1, 2, 3});
        xs = ys;
        CHECK_EQ(xs, Vector<int>({1, 2, 3}));
    }
}

TEST_CASE("Iterator") {
    Vector<int> xs;
    auto it = xs.begin();

    // Iterators on empty vectors are valid, but cannot be deref'd.
    CHECK_THROWS_WITH_AS(*it, "index 0 out of bounds", const InvalidIterator&);

    // Modifying container not only keeps iterators alive, but makes them potentially deref'ble.
    xs.push_back(42);
    CHECK_EQ(*it, 42); // Iterator now points to valid location.

    // Assigning different data to the vector updates the data, but iterators remain valid.
    xs = Vector<int>({15, 25, 35});
    CHECK_EQ(*it, 15); // Iterator now points to valid, but different location.

    CHECK_EQ(*it++, 15);
    CHECK_EQ(*it, 25);
    CHECK_EQ(*++it, 35);

    CHECK_EQ(fmt("%s", it), "<vector iterator>");

    SUBCASE("comparison") {
        Vector<int> xs;
        Vector<int> ys;

        CHECK_EQ(xs.begin(), xs.begin());

        CHECK_THROWS_WITH_AS(operator==(xs.begin(), ys.begin()), "cannot compare iterators into different vectors",
                             const InvalidArgument&);

        auto xs1 = ++xs.begin();
        CHECK_NE(xs.begin(), xs1);
    }
}

TEST_CASE("ConstIterator") {
    Vector<int> xs;
    auto it = xs.cbegin();

    // Iterators on empty vectors are valid, but cannot be deref'd.
    CHECK_THROWS_WITH_AS(*it, "index 0 out of bounds", const InvalidIterator&);

    // Modifying container not only keeps iterators alive, but makes them potentially deref'ble.
    xs.push_back(42);
    CHECK_EQ(*it, 42); // Iterator now points to valid location.

    // Assigning different data to the vector updates the data, but iterators remain valid.
    xs = Vector<int>({15, 25, 35});
    CHECK_EQ(*it, 15); // Iterator now points to valid, but different location.

    CHECK_EQ(*it++, 15);
    CHECK_EQ(*it, 25);
    CHECK_EQ(*++it, 35);

    CHECK_EQ(fmt("%s", it), "<const vector iterator>");

    SUBCASE("comparison") {
        Vector<int> xs;
        Vector<int> ys;

        CHECK_EQ(xs.cbegin(), xs.cbegin());

        CHECK_THROWS_WITH_AS(operator==(xs.cbegin(), ys.cbegin()), "cannot compare iterators into different vectors",
                             const InvalidArgument&);

        auto xs1 = ++xs.cbegin();
        CHECK_NE(xs.cbegin(), xs1);
    }
}

TEST_SUITE_END();
