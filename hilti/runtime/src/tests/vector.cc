// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <memory>

#include <hilti/rt/types/bool.h>
#include <hilti/rt/types/integer.h>
#include <hilti/rt/types/vector.h>

using namespace hilti::rt;

TEST_SUITE_BEGIN("Vector");

TEST_CASE("front") {
    Vector<int> xs;
    CHECK_THROWS_AS(xs.front(), const IndexError&);
    CHECK_THROWS_WITH_AS(xs.front(), "vector is empty", const IndexError&);

    xs.push_back(1);
    CHECK_EQ(xs.front(), 1);
    CHECK_EQ(xs.size(), 1U);
}

TEST_CASE("back") {
    Vector<int> xs;
    CHECK_THROWS_WITH_AS(xs.back(), "vector is empty", const IndexError&);

    xs.push_back(1);
    CHECK_EQ(xs.back(), 1);
    CHECK_EQ(xs.size(), 1U);
}

TEST_CASE("pop_back") {
    Vector<int> xs;
    CHECK_THROWS_WITH_AS(xs.pop_back(), "vector is empty", const IndexError&);

    xs.push_back(1);
    xs.push_back(2);
    CHECK_EQ(xs.size(), 2U);
    xs.pop_back();
    CHECK_EQ(xs.size(), 1U);
    xs.pop_back();
    CHECK_EQ(xs.size(), 0U);
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
    REQUIRE_EQ(xs.size(), 0U);
    CHECK_THROWS_WITH_AS(Vector<int>()[47], "vector index 47 out of range", const IndexError&);
    CHECK_EQ(xs.size(), 0U);

    const auto& ys = xs;
    CHECK_THROWS_WITH_AS(ys[47], "vector index 47 out of range", const IndexError&);

    const Vector<int> zs({0, 1, 2, 3, 4, 5});
    CHECK_EQ(zs[5], 5);

    CHECK_EQ(Vector<int>({0, 1, 2, 3, 4, 5})[5], 5);
}

TEST_CASE("assign") {
    Vector<int> xs({1});
    REQUIRE_EQ(xs.size(), 1U);

    SUBCASE("") {
        xs.assign(0, 42);
        CHECK_EQ(xs.size(), 1U);
        CHECK_EQ(xs[0], 42);
    }

    SUBCASE("w/ resize") {
        xs.assign(3, 42);
        CHECK_EQ(xs.size(), 4);
        CHECK_EQ(xs, Vector({1, 0, 0, 42}));
    }
}

TEST_CASE("assignment") {
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

TEST_CASE("at") {
    Vector<int> xs;
    xs = Vector<int>({1, 2, 3, 4, 5});
    CHECK_EQ(*xs.iteratorAt(1), 2);
    CHECK_THROWS_WITH_AS(xs.iteratorAt(5), "vector index 5 out of range", const IndexError&);
}

TEST_CASE("sub") {
    SUBCASE("range") {
        auto xs = Vector<int>({1, 2, 3, 4, 5});
        CHECK_EQ(xs.sub(1, 4), Vector<int>({2, 3, 4}));
        CHECK_EQ(xs.sub(1, 10), Vector<int>({2, 3, 4, 5}));
        CHECK_EQ(xs.sub(6, 10), Vector<int>({}));
        CHECK_EQ(xs.sub(3, 1), Vector<int>({}));
        CHECK_EQ(xs.sub(3, 3), Vector<int>({}));
    }

    SUBCASE("end") {
        auto xs = Vector<int>({1, 2, 3, 4, 5});
        CHECK_EQ(xs.sub(4), Vector<int>({1, 2, 3, 4}));
        CHECK_EQ(xs.sub(10), Vector<int>({1, 2, 3, 4, 5}));
        CHECK_EQ(xs.sub(0), Vector<int>({}));
    }
}

TEST_CASE("make") {
    const auto fn = [](int x) { return x * 2; };
    const auto pred = [](int x) { return x % 2 == 0; };

    SUBCASE("w/o predicate") {
        CHECK_EQ(vector::make(Vector<int>(), std::vector<int>(), fn), Vector<int>());
        CHECK_EQ(vector::make(Vector<int>(), std::vector({1, 2, 3}), fn), Vector({2, 4, 6}));
    }

    SUBCASE("w/ predicate") {
        CHECK_EQ(vector::make(Vector<int>(), std::vector<int>(), fn, pred), Vector<int>());
        CHECK_EQ(vector::make(Vector<int>(), std::vector({1, 2, 3}), fn, pred), Vector({4}));
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

    // Check const version of iterator dereference.
    const Vector<int>::iterator cit = it;
    CHECK_EQ(*cit, 35);

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

    SUBCASE("ordering") {
        SUBCASE("less") {
            REQUIRE_FALSE(xs.empty());

            CHECK_LT(xs.begin(), xs.end());
            CHECK_FALSE(operator<(xs.end(), xs.begin()));
            CHECK_THROWS_WITH_AS(operator<(Vector<int>().begin(), Vector<int>().begin()),
                                 "cannot compare iterators into different vectors", const InvalidArgument&);
        }

        SUBCASE("less equal") {
            REQUIRE_FALSE(xs.empty());

            CHECK_LE(xs.begin(), xs.end());
            CHECK_FALSE(operator<=(xs.end(), xs.begin()));
            CHECK_THROWS_WITH_AS(operator<=(Vector<int>().begin(), Vector<int>().begin()),
                                 "cannot compare iterators into different vectors", const InvalidArgument&);
        }

        SUBCASE("greater") {
            REQUIRE_FALSE(xs.empty());

            CHECK_GT(xs.end(), xs.begin());
            CHECK_FALSE(operator>(xs.begin(), xs.end()));
            CHECK_THROWS_WITH_AS(operator>(Vector<int>().begin(), Vector<int>().begin()),
                                 "cannot compare iterators into different vectors", const InvalidArgument&);
        }

        SUBCASE("greater equal") {
            REQUIRE_FALSE(xs.empty());

            CHECK_GE(xs.end(), xs.begin());
            CHECK_FALSE(operator>=(xs.begin(), xs.end()));
            CHECK_THROWS_WITH_AS(operator>=(Vector<int>().begin(), Vector<int>().begin()),
                                 "cannot compare iterators into different vectors", const InvalidArgument&);
        }
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

    SUBCASE("ordering") {
        SUBCASE("less") {
            REQUIRE_FALSE(xs.empty());

            CHECK_LT(xs.cbegin(), xs.cend());
            CHECK_FALSE(operator<(xs.cend(), xs.cbegin()));
            CHECK_THROWS_WITH_AS(operator<(Vector<int>().cbegin(), Vector<int>().cbegin()),
                                 "cannot compare iterators into different vectors", const InvalidArgument&);
        }

        SUBCASE("less equal") {
            REQUIRE_FALSE(xs.empty());

            CHECK_LE(xs.cbegin(), xs.cend());
            CHECK_FALSE(operator<=(xs.cend(), xs.cbegin()));
            CHECK_THROWS_WITH_AS(operator<=(Vector<int>().cbegin(), Vector<int>().cbegin()),
                                 "cannot compare iterators into different vectors", const InvalidArgument&);
        }

        SUBCASE("greater") {
            REQUIRE_FALSE(xs.empty());

            CHECK_GT(xs.cend(), xs.cbegin());
            CHECK_FALSE(operator>(xs.cbegin(), xs.cend()));
            CHECK_THROWS_WITH_AS(operator>(Vector<int>().cbegin(), Vector<int>().cbegin()),
                                 "cannot compare iterators into different vectors", const InvalidArgument&);
        }

        SUBCASE("greater equal") {
            REQUIRE_FALSE(xs.empty());

            CHECK_GE(xs.cend(), xs.cbegin());
            CHECK_FALSE(operator>=(xs.cbegin(), xs.cend()));
            CHECK_THROWS_WITH_AS(operator>=(Vector<int>().cbegin(), Vector<int>().cbegin()),
                                 "cannot compare iterators into different vectors", const InvalidArgument&);
        }
    }
}

TEST_CASE("vector of bool") {
    SUBCASE("default allocator") {
        const auto xs = Vector<Bool>({true, false});
        REQUIRE_EQ(xs.size(), 2U);

        CHECK_EQ(xs.front(), Bool(true));
        CHECK_EQ(xs.back(), Bool(false));

        CHECK_EQ(xs[0], Bool(true));
        CHECK_EQ(xs[1], Bool(false));
    }

    SUBCASE("w/ rt::vector::Allocator") {
        auto xs = Vector<Bool, vector::Allocator<Bool>>({}, {true});
        REQUIRE_EQ(xs.size(), 0U);

        xs.assign(2, false);
        CHECK_EQ(xs.size(), 3U);
        CHECK_EQ(xs[0], true);
        CHECK_EQ(xs[1], true);
        CHECK_EQ(xs[2], false);
    }
}

TEST_CASE("insert") {
    Vector<int> xs{1, 2, 3, 4, 5};

    SUBCASE("at begin") {
        CHECK_EQ(*xs.insert(xs.begin(), 0), 0);
        CHECK_EQ(xs, Vector<int>{0, 1, 2, 3, 4, 5});
    }

    SUBCASE("at end") {
        CHECK_EQ(*xs.insert(xs.end(), 0), 0);
        CHECK_EQ(xs, Vector<int>{1, 2, 3, 4, 5, 0});
    }
}

TEST_SUITE_END();
