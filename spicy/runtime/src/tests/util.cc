// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <optional>
#include <string>

#include <hilti/rt/types/bytes.h>

#include <spicy/rt/util.h>

using namespace spicy::rt;
using namespace hilti::rt::bytes::literals;

TEST_SUITE_BEGIN("Util");

TEST_CASE("bytes_to_hexstring") {
    CHECK_EQ(bytes_to_hexstring(""_b), "");
    CHECK_EQ(bytes_to_hexstring("\x01\x02\x03"_b), "010203");
}

TEST_CASE("version") { CHECK_FALSE(version().empty()); }

TEST_SUITE_END();
