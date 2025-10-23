// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <hilti/rt/exception.h>
#include <hilti/rt/types/integer.h>
#include <hilti/rt/types/set.h>
#include <hilti/rt/types/vector.h>

using namespace hilti::rt;

TEST_SUITE_BEGIN("Set");

TEST_CASE("construct") {
    CHECK_EQ(to_string(Set<int>()), "{}");
    CHECK_EQ(to_string(Set<int>({1, 2, 3})), "{1, 2, 3}");

    auto xs = Vector<int>({1, 2, 3});
    CHECK_EQ(to_string(Set<int>(xs)), "{1, 2, 3}");
    CHECK_EQ(to_string(Set<int>(Vector<int>({1, 2, 3}))), "{1, 2, 3}");
}

TEST_CASE("contains") {
    Set<int> s{1, 2, 3};
    CHECK(s.contains(1));
    CHECK_FALSE(s.contains(99));
}

// `insert` does not invalidate dereferenceable iterators.
TEST_CASE("insert") {
    SUBCASE("valid element") {
        Set<int> s({1});
        auto begin = s.begin();

        CHECK_EQ(*begin, 1);

        s.insert(2);

        CHECK_EQ(*begin, 1);
        ++begin;
        CHECK_EQ(*begin, 2);
    }

    // For an empty `Set`, `begin` is not a dereferenceable iterator, and it
    // does not become valid when an element backing it is added to the `Set`.
    SUBCASE("begin") {
        Set<int> s;
        auto begin = s.begin();

        REQUIRE_THROWS_WITH_AS(*begin, "underlying object is invalid", const InvalidIterator&);

        s.insert(2);

        REQUIRE_THROWS_WITH_AS(*begin, "underlying object is invalid", const InvalidIterator&);
        REQUIRE_THROWS_WITH_AS(++begin, "iterator is invalid", const IndexError&);
        REQUIRE_THROWS_WITH_AS(begin++, "iterator is invalid", const IndexError&);
    }

    SUBCASE("hint") {
        Set<int> s;
        auto hint = s.begin();

        auto it1 = s.insert(hint, 1);

        // For an empty `Set`, `begin` is not a dereferenceable iterator, and it
        // does not become valid when an element backing it is added to the `Set`.
        REQUIRE_THROWS_WITH_AS(*hint, "underlying object is invalid", const InvalidIterator&);

        CHECK_EQ(*it1, 1);

        auto it2 = s.insert(hint, 2);
        CHECK_EQ(*it2, 2);
    }
}

TEST_CASE("erase") {
    Set<int> s({1, 2, 3});
    auto it1 = s.begin();
    auto it2 = ++s.begin();
    REQUIRE_EQ(*it1, 1);
    REQUIRE_EQ(*it2, 2);

    REQUIRE_EQ(s.erase(1), 1U);

    // In contrast to a `std::set`, removing elements from a `Set` invalidates
    // _all iterators_, not just iterators to the removed element.
    CHECK_THROWS_WITH_AS(++it1, "iterator is invalid", const IndexError&);
    CHECK_THROWS_WITH_AS(it1++, "iterator is invalid", const IndexError&);
    CHECK_THROWS_WITH_AS(*it1, "underlying object has expired", const InvalidIterator&);

    CHECK_THROWS_WITH_AS(++it2, "iterator is invalid", const IndexError&);
    CHECK_THROWS_WITH_AS(it2++, "iterator is invalid", const IndexError&);
    CHECK_THROWS_WITH_AS(*it2, "underlying object has expired", const InvalidIterator&);
}

TEST_CASE("clear") {
    Set<int> s({1, 2, 3});
    auto it = s.begin();

    REQUIRE_EQ(*it, 1);

    s.clear();

    // Clearing a `Set` invalidates all iterators.
    CHECK_THROWS_WITH_AS(it++, "iterator is invalid", const IndexError&);
    CHECK_THROWS_WITH_AS(++it, "iterator is invalid", const IndexError&);
    CHECK_THROWS_WITH_AS(*it, "underlying object has expired", const InvalidIterator&);
}

TEST_CASE("equal") {
    set::Empty empty;
    Set<int> s1({1, 2, 3});
    Set<int> s2({11, 22, 33});

    CHECK_EQ(empty, empty);
    CHECK_FALSE(operator!=(empty, empty));
    CHECK_EQ(s1, s1);
    CHECK_EQ(s2, s2);
    CHECK_NE(s1, s2);
    CHECK_NE(s1, empty);
    CHECK_NE(empty, s1);

    Set<int> e1;
    Set<int> e2;
    CHECK_NE(e1.begin(), e2.begin());
}

TEST_CASE("iterator") {
    Set<int> s1({1, 2, 3});
    Set<int> s2({1, 2, 3});

    CHECK_THROWS_WITH_AS(operator==(s1.begin(), s2.begin()), "cannot compare iterators into different sets",
                         const InvalidArgument&);

    CHECK_THROWS_WITH_AS(*s1.end(), "iterator is invalid", const IndexError&);

    // If the data for the iterator goes away it becomes invalid.
    auto it = s1.begin();
    REQUIRE_EQ(*it, 1);
    s1 = s2;
    CHECK_THROWS_WITH_AS(*it, "underlying object has expired", const InvalidIterator&);
}

TEST_SUITE_END();
