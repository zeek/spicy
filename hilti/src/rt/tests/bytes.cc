// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <type_traits>

#include <hilti/rt/types/bytes.h>

using namespace hilti::rt;
using namespace hilti::rt::bytes;

TEST_CASE("Bytes") {
    SUBCASE("iteration") {
        // Validate that when iterating we yield the `Iterator`'s `reference` type.
        // This is a regression test for #219.
        for ( auto x : Bytes() ) {
            (void)x;
            static_assert(std::is_same_v<decltype(x), Bytes::Iterator::reference>);
        }
    }

    SUBCASE("to_string") {
        CHECK_EQ(to_string("ABC"_b), "b\"ABC\"");
        CHECK_EQ(to_string("\0\2\3\0\6\7A\01"_b), "b\"\\x00\\x02\\x03\\x00\\x06\\x07A\\x01\"");
    }
}
