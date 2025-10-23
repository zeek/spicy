// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.
//
#include <doctest/doctest.h>

#include <hilti/rt/types/address.h>
#include <hilti/rt/types/network.h>

using namespace hilti::rt;

TEST_SUITE_BEGIN("Network");

TEST_CASE("comparison") {
    const Address addr1("255.255.255.255");
    const Address addr2("0.0.0.0");
    const Address addr3("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
    const Address addr4("0:0:0:0:0:0:0:0");

    CHECK_EQ(Network(addr1, 0), Network(addr1, 0));
    CHECK_EQ(Network(addr1, 12), Network(addr1, 12));
    CHECK_EQ(Network(addr1, 32), Network(addr1, 32));
    CHECK_EQ(Network(addr2, 0), Network(addr4, 0));

    CHECK_NE(Network(addr1, 32), Network(addr1, 0));
    CHECK_NE(Network(addr1, 32), Network(addr2, 32));
    CHECK_NE(Network(addr1, 0), Network(addr3, 0));

    CHECK(Network(addr1, 10) < Network(addr1, 12));
    CHECK(Network(addr2, 16) < Network(addr1, 16));
    CHECK_FALSE(Network(addr2, 32) < Network(addr4, 32));
}

TEST_CASE("construct") {
    SUBCASE("ipv4") {
        const auto addr = Address("1.2.3.4");
        REQUIRE_EQ(addr.family(), AddressFamily::IPv4);

        REQUIRE_EQ(Network(addr, 0).family(), AddressFamily::IPv4);
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

        CHECK_EQ(to_string(Network(addr, 0)), "::/0");
        CHECK_EQ(to_string(Network(addr, 2)), "::/2");
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

    SUBCASE("string") {
        CHECK_EQ(to_string(Network("1.2.3.4", 24)), "1.2.3.0/24");
        CHECK_EQ(to_string(Network("2001:0db8:0000:0000:0000:8a2e:0370:7334", 24)), "2001:d00::/24");
        CHECK_EQ(to_string(Network("::192.168.1.0", 24)), "192.168.1.0/24");
    }

    SUBCASE("default") { CHECK_EQ(to_string(Network()), "<bad network>"); }
}

TEST_CASE("contains") {
    CHECK(Network("255.255.255.255", 32).contains(Address("255.255.255.255")));
    CHECK_FALSE(Network("255.255.255.255", 32).contains(Address("255.255.255.254")));

    CHECK(Network("255.255.255.255", 31).contains(Address("255.255.255.254")));
    CHECK_FALSE(Network("255.255.255.255", 31).contains(Address("255.255.255.253")));

    CHECK(Network("255.255.255.255", 16).contains(Address("255.255.0.0")));
    CHECK_FALSE(Network("255.255.255.255", 16).contains(Address("255.0.0.0")));

    CHECK(Network("255.255.255.255", 8).contains(Address("255.0.0.0")));
    CHECK_FALSE(Network("255.255.255.255", 8).contains(Address("128.0.0.0")));

    CHECK(Network("255.255.255.255", 4).contains(Address("240.0.0.0")));
    CHECK_FALSE(Network("255.255.255.255", 4).contains(Address("239.0.0.0")));

    CHECK(Network("255.255.255.255", 2).contains(Address("239.0.0.0")));
    CHECK_FALSE(Network("255.255.255.255", 2).contains(Address("190.0.0.0")));

    CHECK(Network("255.255.255.255", 1).contains(Address("190.0.0.0")));
    CHECK_FALSE(Network("255.255.255.255", 1).contains(Address("127.0.0.0")));

    CHECK(Network("255.255.255.255", 0).contains(Address("127.0.0.0")));
    CHECK(Network("255.255.255.255", 0).contains(Address("64.0.0.0")));
    CHECK(Network("255.255.255.255", 0).contains(Address("0.0.0.0")));
}

TEST_CASE("family") {
    CHECK_EQ(Network(Address("1.2.3.4"), 32).family(), AddressFamily::IPv4);
    CHECK_EQ(Network(Address("2001:0db8:0000:0000:0000:8a2e:0370:7334"), 32).family(), AddressFamily::IPv6);
}

TEST_CASE("fmt") { CHECK_EQ(fmt("%s", Network("255.255.255.255", 12)), "255.240.0.0/12"); }

TEST_CASE("length") {
    SUBCASE("ipv4") {
        const auto addr = Address("1.2.3.4");

        for ( int length = 0; length < 33; ++length ) {
            CAPTURE(length);
            CHECK_EQ(Network(addr, length).length(), length);
        }
    }

    SUBCASE("ipv6") {
        const auto addr = Address("2001:0db8:0000:0000:0000:8a2e:0370:7334");

        for ( int length = 0; length < 128; ++length ) {
            CAPTURE(length);
            CHECK_EQ(Network(addr, length).length(), length);
        }
    }
}

TEST_CASE("prefix") {
    SUBCASE("ipv4") {
        const auto addr = Address("255.255.255.255");

        const std::vector<Address> expected =
            {Address("0.0.0.0"),         Address("128.0.0.0"),       Address("192.0.0.0"),
             Address("224.0.0.0"),       Address("240.0.0.0"),       Address("248.0.0.0"),
             Address("252.0.0.0"),       Address("254.0.0.0"),       Address("255.0.0.0"),
             Address("255.128.0.0"),     Address("255.192.0.0"),     Address("255.224.0.0"),
             Address("255.240.0.0"),     Address("255.248.0.0"),     Address("255.252.0.0"),
             Address("255.254.0.0"),     Address("255.255.0.0"),     Address("255.255.128.0"),
             Address("255.255.192.0"),   Address("255.255.224.0"),   Address("255.255.240.0"),
             Address("255.255.248.0"),   Address("255.255.252.0"),   Address("255.255.254.0"),
             Address("255.255.255.0"),   Address("255.255.255.128"), Address("255.255.255.192"),
             Address("255.255.255.224"), Address("255.255.255.240"), Address("255.255.255.248"),
             Address("255.255.255.252"), Address("255.255.255.254"), Address("255.255.255.255")};

        for ( int length = 0; length < 33; ++length ) {
            CAPTURE(length);
            CHECK_EQ(Network(addr, length).prefix(), expected.at(length));
        }
    }

    SUBCASE("ipv6") {
        const auto addr = Address("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");

        const std::vector<Address> expected = {Address("::"),
                                               Address("8000::"),
                                               Address("c000::"),
                                               Address("e000::"),
                                               Address("f000::"),
                                               Address("f800::"),
                                               Address("fc00::"),
                                               Address("fe00::"),
                                               Address("ff00::"),
                                               Address("ff80::"),
                                               Address("ffc0::"),
                                               Address("ffe0::"),
                                               Address("fff0::"),
                                               Address("fff8::"),
                                               Address("fffc::"),
                                               Address("fffe::"),
                                               Address("ffff::"),
                                               Address("ffff:8000::"),
                                               Address("ffff:c000::"),
                                               Address("ffff:e000::"),
                                               Address("ffff:f000::"),
                                               Address("ffff:f800::"),
                                               Address("ffff:fc00::"),
                                               Address("ffff:fe00::"),
                                               Address("ffff:ff00::"),
                                               Address("ffff:ff80::"),
                                               Address("ffff:ffc0::"),
                                               Address("ffff:ffe0::"),
                                               Address("ffff:fff0::"),
                                               Address("ffff:fff8::"),
                                               Address("ffff:fffc::"),
                                               Address("ffff:fffe::"),
                                               Address("ffff:ffff::"),
                                               Address("ffff:ffff:8000::"),
                                               Address("ffff:ffff:c000::"),
                                               Address("ffff:ffff:e000::"),
                                               Address("ffff:ffff:f000::"),
                                               Address("ffff:ffff:f800::"),
                                               Address("ffff:ffff:fc00::"),
                                               Address("ffff:ffff:fe00::"),
                                               Address("ffff:ffff:ff00::"),
                                               Address("ffff:ffff:ff80::"),
                                               Address("ffff:ffff:ffc0::"),
                                               Address("ffff:ffff:ffe0::"),
                                               Address("ffff:ffff:fff0::"),
                                               Address("ffff:ffff:fff8::"),
                                               Address("ffff:ffff:fffc::"),
                                               Address("ffff:ffff:fffe::"),
                                               Address("ffff:ffff:ffff::"),
                                               Address("ffff:ffff:ffff:8000::"),
                                               Address("ffff:ffff:ffff:c000::"),
                                               Address("ffff:ffff:ffff:e000::"),
                                               Address("ffff:ffff:ffff:f000::"),
                                               Address("ffff:ffff:ffff:f800::"),
                                               Address("ffff:ffff:ffff:fc00::"),
                                               Address("ffff:ffff:ffff:fe00::"),
                                               Address("ffff:ffff:ffff:ff00::"),
                                               Address("ffff:ffff:ffff:ff80::"),
                                               Address("ffff:ffff:ffff:ffc0::"),
                                               Address("ffff:ffff:ffff:ffe0::"),
                                               Address("ffff:ffff:ffff:fff0::"),
                                               Address("ffff:ffff:ffff:fff8::"),
                                               Address("ffff:ffff:ffff:fffc::"),
                                               Address("ffff:ffff:ffff:fffe::"),
                                               Address("ffff:ffff:ffff:ffff::"),
                                               Address("ffff:ffff:ffff:ffff:8000::"),
                                               Address("ffff:ffff:ffff:ffff:c000::"),
                                               Address("ffff:ffff:ffff:ffff:e000::"),
                                               Address("ffff:ffff:ffff:ffff:f000::"),
                                               Address("ffff:ffff:ffff:ffff:f800::"),
                                               Address("ffff:ffff:ffff:ffff:fc00::"),
                                               Address("ffff:ffff:ffff:ffff:fe00::"),
                                               Address("ffff:ffff:ffff:ffff:ff00::"),
                                               Address("ffff:ffff:ffff:ffff:ff80::"),
                                               Address("ffff:ffff:ffff:ffff:ffc0::"),
                                               Address("ffff:ffff:ffff:ffff:ffe0::"),
                                               Address("ffff:ffff:ffff:ffff:fff0::"),
                                               Address("ffff:ffff:ffff:ffff:fff8::"),
                                               Address("ffff:ffff:ffff:ffff:fffc::"),
                                               Address("ffff:ffff:ffff:ffff:fffe::"),
                                               Address("ffff:ffff:ffff:ffff:ffff::"),
                                               Address("ffff:ffff:ffff:ffff:ffff:8000::"),
                                               Address("ffff:ffff:ffff:ffff:ffff:c000::"),
                                               Address("ffff:ffff:ffff:ffff:ffff:e000::"),
                                               Address("ffff:ffff:ffff:ffff:ffff:f000::"),
                                               Address("ffff:ffff:ffff:ffff:ffff:f800::"),
                                               Address("ffff:ffff:ffff:ffff:ffff:fc00::"),
                                               Address("ffff:ffff:ffff:ffff:ffff:fe00::"),
                                               Address("ffff:ffff:ffff:ffff:ffff:ff00::"),
                                               Address("ffff:ffff:ffff:ffff:ffff:ff80::"),
                                               Address("ffff:ffff:ffff:ffff:ffff:ffc0::"),
                                               Address("ffff:ffff:ffff:ffff:ffff:ffe0::"),
                                               Address("ffff:ffff:ffff:ffff:ffff:fff0::"),
                                               Address("ffff:ffff:ffff:ffff:ffff:fff8::"),
                                               Address("ffff:ffff:ffff:ffff:ffff:fffc::"),
                                               Address("ffff:ffff:ffff:ffff:ffff:fffe::"),
                                               Address("ffff:ffff:ffff:ffff:ffff:ffff::"),
                                               Address("ffff:ffff:ffff:ffff:ffff:ffff:8000:0"),
                                               Address("ffff:ffff:ffff:ffff:ffff:ffff:c000:0"),
                                               Address("ffff:ffff:ffff:ffff:ffff:ffff:e000:0"),
                                               Address("ffff:ffff:ffff:ffff:ffff:ffff:f000:0"),
                                               Address("ffff:ffff:ffff:ffff:ffff:ffff:f800:0"),
                                               Address("ffff:ffff:ffff:ffff:ffff:ffff:fc00:0"),
                                               Address("ffff:ffff:ffff:ffff:ffff:ffff:fe00:0"),
                                               Address("ffff:ffff:ffff:ffff:ffff:ffff:ff00:0"),
                                               Address("ffff:ffff:ffff:ffff:ffff:ffff:ff80:0"),
                                               Address("ffff:ffff:ffff:ffff:ffff:ffff:ffc0:0"),
                                               Address("ffff:ffff:ffff:ffff:ffff:ffff:ffe0:0"),
                                               Address("ffff:ffff:ffff:ffff:ffff:ffff:fff0:0"),
                                               Address("ffff:ffff:ffff:ffff:ffff:ffff:fff8:0"),
                                               Address("ffff:ffff:ffff:ffff:ffff:ffff:fffc:0"),
                                               Address("ffff:ffff:ffff:ffff:ffff:ffff:fffe:0"),
                                               Address("ffff:ffff:ffff:ffff:ffff:ffff:ffff:0"),
                                               Address("ffff:ffff:ffff:ffff:ffff:ffff:ffff:8000"),
                                               Address("ffff:ffff:ffff:ffff:ffff:ffff:ffff:c000"),
                                               Address("ffff:ffff:ffff:ffff:ffff:ffff:ffff:e000"),
                                               Address("ffff:ffff:ffff:ffff:ffff:ffff:ffff:f000"),
                                               Address("ffff:ffff:ffff:ffff:ffff:ffff:ffff:f800"),
                                               Address("ffff:ffff:ffff:ffff:ffff:ffff:ffff:fc00"),
                                               Address("ffff:ffff:ffff:ffff:ffff:ffff:ffff:fe00"),
                                               Address("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff00"),
                                               Address("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff80"),
                                               Address("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffc0"),
                                               Address("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffe0"),
                                               Address("ffff:ffff:ffff:ffff:ffff:ffff:ffff:fff0"),
                                               Address("ffff:ffff:ffff:ffff:ffff:ffff:ffff:fff8"),
                                               Address("ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffc"),
                                               Address("ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe")};

        for ( int length = 0; length < 128; ++length ) {
            CAPTURE(length);
            CHECK_EQ(Network(addr, length).prefix(), expected.at(length));
        }
    }
}

TEST_SUITE_END();
