// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <hilti/rt/doctest.h>
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

TEST_SUITE_END();
