// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <arpa/inet.h>
#include <doctest/doctest.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <string>

#include <hilti/rt/types/address.h>
#include <hilti/rt/types/bytes.h>
#include <hilti/rt/types/tuple.h>

using namespace hilti::rt;
using namespace hilti::rt::bytes::literals;

namespace hilti::rt {
template<typename T>
std::ostream& operator<<(std::ostream& out, const Result<T>& x) {
    if ( x.hasValue() )
        return out << fmt("Ok(%s)", *x);
    else
        return out << x.error();
}
} // namespace hilti::rt

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

TEST_SUITE_BEGIN("Address");

TEST_CASE("conversions to and from `std::string`") {
    CHECK_EQ(std::string(Address("1.2.3.4")), "1.2.3.4");
    CHECK_EQ(std::string(Address("::192.168.1.0")), "192.168.1.0");
    CHECK_EQ(std::string(Address("2001:db8:85a3:8d3:1319:8a2e:370:7348")), "2001:db8:85a3:8d3:1319:8a2e:370:7348");

    CHECK_THROWS(Address("example.com"));
    CHECK_THROWS(Address("-1234567890"));
    CHECK_THROWS(Address("-2001:db8:85a3:8d3:1319:8a2e:370:7348"));
}

TEST_CASE("constructs from an `::in_addr4`") { CHECK_EQ(std::string(Address(*make_in_addr("1.2.3.4"))), "1.2.3.4"); }

TEST_CASE("constructs from an `::in6_addr`") {
    std::string addr = std::string(Address(*make_in6_addr("::4996:2d2:0:0:4996:2d2")));
    auto is_correct = (addr == "::4996:2d2:0:0:4996:2d2" ||
                       addr == "0:0:4996:2d2::4996:2d2"); // Alpine has been seen to return the latter

    CHECK(is_correct);
}

TEST_CASE("constructs from binary representation of an IPv4 address") {
    CHECK_EQ(Address(1234567890).family(), AddressFamily::IPv4);
    CHECK_EQ(std::string(Address(1234567890)), "73.150.2.210");
}

TEST_CASE("constructs from binary representation of an IPv6 address") {
    CHECK_EQ(Address(1234567890, 1234567890).family(), AddressFamily::IPv6);

    std::string addr = Address(1234567890, 1234567890);
    bool is_correct = (addr == "::4996:2d2:0:0:4996:2d2" ||
                       addr == "0:0:4996:2d2::4996:2d2"); // Alpine has been seen to return the latter
    CHECK(is_correct);
}

TEST_CASE("family") {
    CHECK_EQ(Address().family(), AddressFamily::Undef);
    CHECK_EQ(Address("1.2.3.4").family(), AddressFamily::IPv4);
    CHECK_EQ(Address("2001:db8:85a3:8d3:1319:8a2e:370:7348").family(), AddressFamily::IPv6);
    CHECK_EQ(Address("::ffff:1.2.3.4").family(), AddressFamily::IPv6);
    CHECK_EQ(Address("::1.2.3.4").family(), AddressFamily::IPv4);
}

TEST_CASE("mask") {
    CHECK_EQ(Address("9.9.9.9").mask(0), Address("0.0.0.0"));
    CHECK_EQ(Address("9.9.9.9").mask(48), Address("0.0.0.0"));
    CHECK_EQ(Address("9.9.9.9").mask(96), Address("0.0.0.0"));
    CHECK_EQ(Address("9.9.9.9").mask(104), Address("9.0.0.0"));
    CHECK_EQ(Address("9.9.9.9").mask(112), Address("9.9.0.0"));
    CHECK_EQ(Address("9.9.9.9").mask(112), Address("9.9.0.0"));
    CHECK_EQ(Address("9.9.9.9").mask(120), Address("9.9.9.0"));
    CHECK_EQ(Address("9.9.9.9").mask(128), Address("9.9.9.9"));

    CHECK_EQ(Address("2001:db8:85a3:8d3:1319:8a2e:370:7348").mask(0), Address("::"));
    CHECK_EQ(Address("2001:db8:85a3:8d3:1319:8a2e:370:7348").mask(16), Address("2001::"));
    CHECK_EQ(Address("2001:db8:85a3:8d3:1319:8a2e:370:7348").mask(32), Address("2001:db8::"));
    CHECK_EQ(Address("2001:db8:85a3:8d3:1319:8a2e:370:7348").mask(48), Address("2001:db8:85a3::"));
    CHECK_EQ(Address("2001:db8:85a3:8d3:1319:8a2e:370:7348").mask(64), Address("2001:db8:85a3:8d3::"));
    CHECK_EQ(Address("2001:db8:85a3:8d3:1319:8a2e:370:7348").mask(80), Address("2001:db8:85a3:8d3:1319::"));
    CHECK_EQ(Address("2001:db8:85a3:8d3:1319:8a2e:370:7348").mask(96), Address("2001:db8:85a3:8d3:1319:8a2e::"));
    CHECK_EQ(Address("2001:db8:85a3:8d3:1319:8a2e:370:7348").mask(112), Address("2001:db8:85a3:8d3:1319:8a2e:370::"));
    CHECK_EQ(Address("2001:db8:85a3:8d3:1319:8a2e:370:7348").mask(128),
             Address("2001:db8:85a3:8d3:1319:8a2e:370:7348"));
}

TEST_CASE("asInAddr") {
    CHECK_EQ(std::get<struct in_addr>(Address().asInAddr()), *make_in_addr("0.0.0.0"));
    CHECK_EQ(std::get<struct in_addr>(Address("1.2.3.4").asInAddr()), *make_in_addr("1.2.3.4"));
    CHECK_NE(std::get<struct in_addr>(Address("1.2.3.4").asInAddr()), *make_in_addr("0.0.0.0"));
    CHECK_NE(std::get<struct in6_addr>(Address("2001:db8:85a3:8d3:1319:8a2e:370:7348").asInAddr()),
             *make_in6_addr("2001::"));
    CHECK_EQ(std::get<struct in6_addr>(Address("2001:db8:85a3:8d3:1319:8a2e:370:7348").asInAddr()),
             *make_in6_addr("2001:db8:85a3:8d3:1319:8a2e:370:7348"));
}

TEST_CASE("pack") {
    CHECK_EQ(address::pack(Address("1.2.3.4"), ByteOrder::Big), "\x01\x02\x03\x04"_b);
    CHECK_EQ(address::pack(Address("4.3.2.1"), ByteOrder::Little), "\x01\x02\x03\x04"_b);
    CHECK_EQ(address::pack(Address("1.2.3.4"), ByteOrder::Host), "\x04\x03\x02\x01"_b);
    CHECK_EQ(address::pack(Address("102:304:102:304:506:708:901:203"), ByteOrder::Big),
             "\x01\x02\x03\x04\x01\x02\x03\x04\x05\x06\x07\x08\x09\x01\x02\x03"_b);
    CHECK_EQ(address::pack(Address("302:109:807:605:403:201:403:201"), ByteOrder::Little),
             "\x01\x02\x03\x04\x01\x02\x03\x04\x05\x06\x07\x08\x09\x01\x02\x03"_b);
    CHECK_EQ(address::pack(Address("2001:db8::FFFF:192.168.0.5"), ByteOrder::Little),
             "\x05\x00\xa8\xc0\xff\xff\x00\x00\x00\x00\x00\x00\xb8\x0d\x01\x20"_b);
    CHECK_THROWS_WITH_AS(address::pack(Address("1.2.3.4"), ByteOrder::Undef),
                         "attempt to pack value with undefined byte order", const RuntimeError&);
}

TEST_CASE("unpack") {
    SUBCASE("Bytes") {
        CHECK_EQ(address::unpack("\x01\x02\x03\x04"_b, AddressFamily::Undef, ByteOrder::Big),
                 Result<Tuple<Address, Bytes>>(result::Error("undefined address family for unpacking")));

        CHECK_EQ(address::unpack("\x01\x02\x03\x04"_b, AddressFamily::IPv4, ByteOrder::Undef),
                 Result<Tuple<Address, Bytes>>(result::Error("undefined byte order")));


        CHECK_EQ(address::unpack("\x01\x02\x03"_b, AddressFamily::IPv4, ByteOrder::Big),
                 Result<Tuple<Address, Bytes>>(result::Error("insufficient data to unpack IPv4 address")));

        CHECK_EQ(*address::unpack("\x01\x02\x03\x04", AddressFamily::IPv4, ByteOrder::Big),
                 tuple::make(Address("1.2.3.4"), ""_b));

        CHECK_EQ(*address::unpack("\x01\x02\x03\x04", AddressFamily::IPv4, ByteOrder::Little),
                 tuple::make(Address("4.3.2.1"), ""_b));

        const auto excess = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x01\x02\x03"_b;
        CHECK_EQ(*address::unpack("\x01\x02\x03\x04"_b + excess, AddressFamily::IPv4, ByteOrder::Big),
                 tuple::make(Address("1.2.3.4"), excess));

        CHECK_EQ(address::unpack("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x00\x01\x02\x03\x04\x05"_b, AddressFamily::IPv6,
                                 ByteOrder::Big),
                 Result<Tuple<Address, Bytes>>(result::Error("insufficient data to unpack IPv6 address")));

        CHECK_EQ(*address::unpack("\x01\x02\x03\x04\x01\x02\x03\x04\x05\x06\x07\x08\x09\x01\x02\x03"_b,
                                  AddressFamily::IPv6, ByteOrder::Big),
                 tuple::make(Address("102:304:102:304:506:708:901:203"), ""_b));

        CHECK_EQ(*address::unpack("\x01\x02\x03\x04\x01\x02\x03\x04\x05\x06\x07\x08\x09\x01\x02\x03"_b,
                                  AddressFamily::IPv6, ByteOrder::Little),
                 tuple::make(Address("302:109:807:605:403:201:403:201"), ""_b));

        CHECK_EQ(*address::unpack("\x01\x02\x03\x04\x01\x02\x03\x04\x05\x06\x07\x08\x09\x01\x02\x03"_b + excess,
                                  AddressFamily::IPv6, ByteOrder::Big),
                 tuple::make(Address("102:304:102:304:506:708:901:203"), excess));
    }

    SUBCASE("View") {
        auto stream = Stream("\x01\x02\x03\x04\x05\x06\x07\x08\x09"_b);

        bool expanding = false;
        SUBCASE("expanding") { expanding = true; }
        SUBCASE("not expanding") { expanding = false; }

        CHECK_EQ(*address::unpack(stream.view(expanding), AddressFamily::IPv4, ByteOrder::Big),
                 tuple::make(Address("1.2.3.4"), Stream("\x05\x06\x07\x08\x09"_b).view(expanding)));

        ;
    }
}

TEST_CASE("comparison") {
    const auto a1 = Address();
    const auto a2 = Address("127.0.0.1");
    const auto a3 = Address("127.0.0.2");

    CHECK_EQ(a1, a1);
    CHECK_EQ(a2, a2);

    CHECK_NE(a1, a2);
    CHECK_NE(a2, a1);

    CHECK(a1 < a2);
    CHECK(a2 < a3);
    CHECK(! (a2 < a2));
}

TEST_SUITE_END();
