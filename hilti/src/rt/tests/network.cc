// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.
//
#include <doctest/doctest.h>

#include <hilti/rt/types/address.h>
#include <hilti/rt/types/network.h>

using namespace hilti::rt;

TEST_SUITE_BEGIN("Network");

TEST_CASE("construct") {
    SUBCASE("ipv4") {
        const auto addr = Address("1.2.3.4");
        REQUIRE_EQ(addr.family(), AddressFamily::IPv4);

        CHECK_EQ(to_string(Network(addr, 0)), "0.0.0.0/0");
        CHECK_EQ(to_string(Network(addr, 2)), "0.0.0.0/2");
        CHECK_EQ(to_string(Network(addr, 4)), "0.0.0.0/4");
        CHECK_EQ(to_string(Network(addr, 8)), "1.0.0.0/8");
        CHECK_EQ(to_string(Network(addr, 16)), "1.2.0.0/16");
        CHECK_EQ(to_string(Network(addr, 32)), "1.2.3.4/32");

        CHECK_EQ(Network(addr, 4), Network(to_string(addr), 4));

        CHECK_THROWS_WITH_AS(to_string(Network(addr, -1)), "prefix length -1 is invalid for IPv4 networks",
                             const InvalidArgument&);
        CHECK_THROWS_WITH_AS(to_string(Network(addr, 33)), "prefix length 33 is invalid for IPv4 networks",
                             const InvalidArgument&);
    }

    SUBCASE("ipv6") {
        const auto addr = Address("2001:0db8:0000:0000:0000:8a2e:0370:7334");
        REQUIRE_EQ(addr.family(), AddressFamily::IPv6);

        // TODO(bbannier): These tests fail since a fully masked
        // IPv4 address is silently converted to an IPv6 address.
        // CHECK_EQ(to_string(Network(addr, 0)), "0.0.0.0/0");
        // CHECK_EQ(to_string(Network(addr, 2)), "0.0.0.0/2");
        CHECK_EQ(to_string(Network(addr, 4)), "2000::/4");
        CHECK_EQ(to_string(Network(addr, 8)), "2000::/8");
        CHECK_EQ(to_string(Network(addr, 16)), "2001::/16");
        CHECK_EQ(to_string(Network(addr, 32)), "2001:db8::/32");
        CHECK_EQ(to_string(Network(addr, 64)), "2001:db8::/64");
        CHECK_EQ(to_string(Network(addr, 128)), "2001:db8::8a2e:370:7334/128");

        CHECK_EQ(Network(addr, 4), Network(to_string(addr), 4));

        CHECK_THROWS_WITH_AS(to_string(Network(addr, -1)), "prefix length -1 is invalid for IPv6 networks",
                             const InvalidArgument&);
        CHECK_THROWS_WITH_AS(to_string(Network(addr, 129)), "prefix length 129 is invalid for IPv6 networks",
                             const InvalidArgument&);
    }
}

TEST_SUITE_END();
