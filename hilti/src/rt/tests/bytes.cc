// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <type_traits>

#include <hilti/rt/types/bytes.h>

using namespace hilti::rt;
using namespace hilti::rt::bytes;

TEST_SUITE_BEGIN("Bytes");

TEST_CASE("iteration") {
    // Validate that when iterating we yield the `Iterator`'s `reference` type.
    // This is a regression test for #219.
    for ( auto x : Bytes() ) {
        (void)x;
        static_assert(std::is_same_v<decltype(x), Bytes::Iterator::reference>);
    }
}

TEST_SUITE_END();
