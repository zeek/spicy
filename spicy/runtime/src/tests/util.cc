// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

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

TEST_CASE("bytes_to_mac") {
    CHECK_EQ(bytes_to_mac(""_b), "");
    CHECK_EQ(bytes_to_mac("\x01\x02\x0a"_b), "01:02:0A");
    CHECK_EQ(bytes_to_mac("\x01"_b), "01");
}

TEST_CASE("version") { CHECK_FALSE(version().empty()); }

TEST_SUITE_END();
