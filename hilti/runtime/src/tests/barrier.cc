// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#include <hilti/rt/doctest.h>
#include <hilti/rt/types/barrier.h>

using namespace hilti::rt;

TEST_SUITE_BEGIN("Barrier");

TEST_CASE("construct") {
    auto b1 = Barrier(0);
    CHECK(b1.isReleased());
    CHECK(b1);

    auto b2 = Barrier(3);
    CHECK(! b2.isReleased());
    CHECK(! b2);
}

TEST_SUITE_END();
