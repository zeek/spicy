// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <arpa/inet.h>

#include <string>

#include <hilti/rt/types/address.h>

#include <doctest/doctest.h>

using namespace hilti::rt;

std::ostream& operator<<(std::ostream& out, const in_addr& addr) { return out << Address(addr); }

std::ostream& operator<<(std::ostream& out, const in6_addr& addr) { return out << Address(addr); }

static auto make_in6_addr(const char* d) {
    auto addr = std::make_unique<::in6_addr>();
    REQUIRE(::inet_pton(AF_INET6, d, addr.get()));
    return addr;
}

static auto make_in_addr(const char* d) {
    auto addr = std::make_unique<::in_addr>();
    REQUIRE(::inet_aton(d, addr.get()));
    return addr;
}

static bool operator==(const in_addr& a1, const in_addr& a2) { return a1.s_addr == a2.s_addr; }

static bool operator!=(const in_addr& a1, const in_addr& a2) { return ! (a1 == a2); }

static bool operator==(const in6_addr& a1, const in6_addr& a2) {
    for ( auto i = 0; i < 8; ++i ) {
        if ( a1.s6_addr[i] != a2.s6_addr[i] )
            return false;
    }

    return true;
}

static bool operator!=(const in6_addr& a1, const in6_addr& a2) { return ! (a1 == a2); }

TEST_CASE("Address") {
    SUBCASE("conversions to and from `std::string`") {
        CHECK(std::string(Address("1.2.3.4")) == "1.2.3.4");
        CHECK(std::string(Address("2001:db8:85a3:8d3:1319:8a2e:370:7348")) == "2001:db8:85a3:8d3:1319:8a2e:370:7348");

        CHECK_THROWS(Address("example.com"));
        CHECK_THROWS(Address("-1234567890"));
        CHECK_THROWS(Address("-2001:db8:85a3:8d3:1319:8a2e:370:7348"));
    }

    SUBCASE("constructs from an `::in_addr4`") { CHECK(std::string(Address(*make_in_addr("1.2.3.4"))) == "1.2.3.4"); }

    SUBCASE("constructs from an `::in6_addr`") {
        CHECK(std::string(Address(*make_in6_addr("::4996:2d2:0:0:4996:2d2"))) == "::4996:2d2:0:0:4996:2d2");
    }

    SUBCASE("constructs from binary represenation of an IPv4 address") {
        CHECK(std::string(Address(1234567890)) == "73.150.2.210");
    }

    SUBCASE("constructs from binary represenation of an IPv6 address") {
        CHECK(std::string(Address(1234567890, 1234567890)) == "::4996:2d2:0:0:4996:2d2");
    }

    SUBCASE("family") {
        CHECK(Address().family() == AddressFamily::IPv4); // Default address of 0.0.0.0 is IPv4.
        CHECK(Address("1.2.3.4").family() == AddressFamily::IPv4);
        CHECK(Address("2001:db8:85a3:8d3:1319:8a2e:370:7348").family() == AddressFamily::IPv6);
        CHECK(Address("::ffff:1.2.3.4").family() == AddressFamily::IPv6);
    }

    SUBCASE("mask") {
        CHECK(Address("9.9.9.9").mask(0) == Address("0.0.0.0"));
        CHECK(Address("9.9.9.9").mask(48) == Address("0.0.0.0"));
        CHECK(Address("9.9.9.9").mask(96) == Address("0.0.0.0"));
        CHECK(Address("9.9.9.9").mask(104) == Address("9.0.0.0"));
        CHECK(Address("9.9.9.9").mask(112) == Address("9.9.0.0"));
        CHECK(Address("9.9.9.9").mask(112) == Address("9.9.0.0"));
        CHECK(Address("9.9.9.9").mask(120) == Address("9.9.9.0"));
        CHECK(Address("9.9.9.9").mask(128) == Address("9.9.9.9"));

        // TODO(bbannier): An IPv6 address with a zero mask should still be an IPv6 address.
        CHECK(Address("2001:db8:85a3:8d3:1319:8a2e:370:7348").mask(0) == Address("0.0.0.0"));
        CHECK(Address("2001:db8:85a3:8d3:1319:8a2e:370:7348").mask(16) == Address("2001::"));
        CHECK(Address("2001:db8:85a3:8d3:1319:8a2e:370:7348").mask(32) == Address("2001:db8::"));
        CHECK(Address("2001:db8:85a3:8d3:1319:8a2e:370:7348").mask(48) == Address("2001:db8:85a3::"));
        CHECK(Address("2001:db8:85a3:8d3:1319:8a2e:370:7348").mask(64) == Address("2001:db8:85a3:8d3::"));
        CHECK(Address("2001:db8:85a3:8d3:1319:8a2e:370:7348").mask(80) == Address("2001:db8:85a3:8d3:1319::"));
        CHECK(Address("2001:db8:85a3:8d3:1319:8a2e:370:7348").mask(96) == Address("2001:db8:85a3:8d3:1319:8a2e::"));
        CHECK(Address("2001:db8:85a3:8d3:1319:8a2e:370:7348").mask(112) ==
              Address("2001:db8:85a3:8d3:1319:8a2e:370::"));
        CHECK(Address("2001:db8:85a3:8d3:1319:8a2e:370:7348").mask(128) ==
              Address("2001:db8:85a3:8d3:1319:8a2e:370:7348"));
    }

    SUBCASE("asInAddr") {
        CHECK(std::get<struct in_addr>(Address().asInAddr()) == *make_in_addr("0.0.0.0"));
        CHECK(std::get<struct in_addr>(Address("1.2.3.4").asInAddr()) == *make_in_addr("1.2.3.4"));
        CHECK(std::get<struct in_addr>(Address("1.2.3.4").asInAddr()) != *make_in_addr("0.0.0.0"));
        CHECK(std::get<struct in6_addr>(Address("2001:db8:85a3:8d3:1319:8a2e:370:7348").asInAddr()) !=
              *make_in6_addr("2001::"));
        CHECK(std::get<struct in6_addr>(Address("2001:db8:85a3:8d3:1319:8a2e:370:7348").asInAddr()) ==
              *make_in6_addr("2001:db8:85a3:8d3:1319:8a2e:370:7348"));
    }
}
