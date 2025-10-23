// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <limits>

#include <hilti/rt/fmt.h>

using namespace hilti::rt;

TEST_SUITE_BEGIN("fmt");

TEST_CASE("fmt") {
    // We currently test only that this works in principle since
    // we very thinly wrapped tinyformat.
    //
    // TODO(bbannier): Extend this suite with other test cases once we
    // have determined a proper subset we want to officially support.
    CHECK_EQ(fmt("%s", 123), "123");
}

TEST_CASE("padding") {
    // This is regression test for https://github.com/zeek/spicy/issues/571.
    CHECK_EQ(fmt("%.16d", 1), "0000000000000001");
    CHECK_EQ(fmt("%.16d", 0.5), "00000000000000.5");
    CHECK_EQ(fmt("%.16d", -0.5), "-0000000000000.5");
    CHECK_EQ(fmt("%.16d", std::numeric_limits<double>::quiet_NaN()), "             nan");
    CHECK_EQ(fmt("%.16d", std::numeric_limits<double>::infinity()), "             inf");
}

TEST_SUITE_END();
