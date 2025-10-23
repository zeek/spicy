// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <hilti/rt/types/port.h>

using namespace hilti::rt;

TEST_SUITE_BEGIN("Port");

TEST_CASE("construct") {
    SUBCASE("default") {
        CHECK_EQ(Port().port(), 0U);
        CHECK_EQ(Port().protocol(), Protocol::Undef);
    }

    SUBCASE("from port and protocol") {
        CHECK_EQ(Port(65535, Protocol::TCP).port(), 65535);
        CHECK_EQ(Port(65535, Protocol::TCP).protocol(), Protocol::TCP);
    }

    SUBCASE("from string") {
        CHECK_EQ(Port("22/tcp"), Port(22, Protocol::TCP));
        CHECK_EQ(Port("22/udp"), Port(22, Protocol::UDP));
        CHECK_EQ(Port("22/icmp"), Port(22, Protocol::ICMP));

        CHECK_EQ(Port("0/tcp"), Port(0, Protocol::TCP));
        CHECK_EQ(Port("65535/tcp"), Port(65535, Protocol::TCP));

        // Missing value & protocol.
        CHECK_THROWS_WITH_AS(Port(""), "cannot parse port specification", const RuntimeError&);

        // Port value out of range.
        CHECK_THROWS_WITH_AS(Port("65536/tcp"), "cannot parse port specification", const RuntimeError&);
        CHECK_THROWS_WITH_AS(Port("6553600000000/tcp"), "cannot parse port specification", const RuntimeError&);
        CHECK_THROWS_WITH_AS(Port("-1/tcp"), "cannot parse port specification", const RuntimeError&);

        // One of value or protocol missing.
        CHECK_THROWS_WITH_AS(Port("22/"), "cannot parse port specification", const RuntimeError&);
        CHECK_THROWS_WITH_AS(Port("/tcp"), "cannot parse port specification", const RuntimeError&);

        // Invalid protocols.
        CHECK_THROWS_WITH_AS(Port("22/tcpX"), "cannot parse port specification", const RuntimeError&);
        CHECK_THROWS_WITH_AS(Port("22/xyz"), "cannot parse port specification", const RuntimeError&);
    }
}

TEST_CASE("comparison") {
    const auto p0 = Port();
    const auto p1 = Port(22, Protocol::TCP);
    const auto p2 = Port(23, Protocol::TCP);

    CHECK_EQ(p0, p0);
    CHECK_EQ(p1, p1);
    CHECK_NE(p0, p1);
    CHECK_NE(p1, p0);

    CHECK(p0 < p1);
    CHECK(p1 < p2);
    CHECK(! (p1 < p1));
}

TEST_SUITE_END();
