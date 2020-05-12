// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <hilti/rt/types/map.h>

#include <doctest/doctest.h>

using namespace hilti::rt;

TEST_SUITE_BEGIN("Map");

TEST_CASE("get") {
    Map<int, int> m;
    DOCTEST_CHECK_THROWS_WITH_AS(m.get(1), "key is unset", const IndexError&);

    m[1] = 2;
    CHECK_EQ(m.get(1), 2);
}

TEST_SUITE_END();
