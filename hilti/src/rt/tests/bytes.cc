// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <type_traits>

#include <hilti/rt/types/bytes.h>

using namespace hilti::rt;
using namespace hilti::rt::bytes;

TEST_SUITE_BEGIN("Bytes");

TEST_CASE("at") {
    const auto b = "123"_b;
    CHECK_EQ(b.at(0), b.begin());
    CHECK_EQ(*b.at(0), '1');
    CHECK_EQ(*b.at(1), '2');
    CHECK_EQ(*b.at(2), '3');
    CHECK_EQ(b.at(3), b.end());
    // CHECK_THROWS_WITH_AS(*b.at(5), "invalid index", const IndexError&); // TODO(bbannier): Catch invalid access.
}

TEST_CASE("find") {
    const auto b = "123"_b;
    const auto empty = ""_b;

    SUBCASE("single byte") {
        SUBCASE("default start") {
            CHECK_EQ(b.find('2'), b.at(1));
            CHECK_EQ(b.find('a'), b.end());
            CHECK_EQ(empty.find('a'), empty.end());
        }

        SUBCASE("start at target") {
            CHECK_EQ(b.find('2', b.at(1)), b.at(1));
            CHECK_EQ(b.find('a', b.at(1)), b.end());
        }

        SUBCASE("start beyond target") {
            CHECK_EQ(b.find('2', b.at(2)), b.end());
            CHECK_EQ(b.find('a', b.at(2)), b.end());
            CHECK_EQ(b.find('a', b.end()), b.end());
        }
    }

    SUBCASE("range of bytes") {
        SUBCASE("default start") {
            CHECK_EQ(b.find("23"_b), std::make_tuple(true, b.at(1)));
            CHECK_EQ(b.find("234"_b), std::make_tuple(false, b.at(1)));
            CHECK_EQ(b.find("22"_b), std::make_tuple(false, b.end()));
            CHECK_EQ(b.find("a"_b), std::make_tuple(false, b.end()));
            CHECK_EQ(b.find(""_b), std::make_tuple(true, b.begin()));
            CHECK_EQ(empty.find("a"_b), std::make_tuple(false, empty.end()));
            CHECK_EQ(empty.find(""_b), std::make_tuple(true, empty.begin()));
        }

        SUBCASE("start at target") {
            CHECK_EQ(b.find("23", b.at(1)), std::make_tuple(true, b.at(1)));
            CHECK_EQ(b.find("ab", b.at(1)), std::make_tuple(false, b.end()));
        }

        SUBCASE("start beyond target") {
            CHECK_EQ(b.find("23", b.at(2)), std::make_tuple(false, b.end()));
            CHECK_EQ(b.find("ab", b.at(2)), std::make_tuple(false, b.end()));
            CHECK_EQ(b.find("ab", b.end()), std::make_tuple(false, b.end()));
        }
    }
}

TEST_CASE("match") {
    const auto b = "123"_b;
    CHECK_EQ(b.match(RegExp("2"), 0), Result("2"_b));
    CHECK_EQ(b.match(RegExp("a"), 0), Result<Bytes>(result::Error("no matches found")));
    CHECK_EQ(b.match(RegExp("2"), 1), Result<Bytes>(result::Error("no matches found")));
}

TEST_CASE("iteration") {
    // Validate that when iterating we yield the `Iterator`'s `reference` type.
    // This is a regression test for #219.
    for ( auto x : Bytes() ) {
        (void)x;
        static_assert(std::is_same_v<decltype(x), Bytes::Iterator::reference>);
    }
}

TEST_SUITE_END();
