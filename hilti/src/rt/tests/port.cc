// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <hilti/rt/types/port.h>

using namespace hilti::rt;

TEST_SUITE_BEGIN("Port");

TEST_CASE("construct") {
    SUBCASE("from string") {
        CHECK_EQ(Port("22/tcp"), Port(22, Protocol::TCP));
        CHECK_EQ(Port("22/udp"), Port(22, Protocol::UDP));
        CHECK_EQ(Port("22/icmp"), Port(22, Protocol::ICMP));

        CHECK_EQ(Port("0/tcp"), Port(0, Protocol::TCP));
        CHECK_EQ(Port("65535/tcp"), Port(65535, Protocol::TCP));

        CHECK_THROWS_WITH_AS(Port(""), "cannot parse port specification", const RuntimeError&);
        CHECK_THROWS_WITH_AS(Port("65536/tcp"), "cannot parse port specification", const RuntimeError&);
        CHECK_THROWS_WITH_AS(Port("6553600000000/tcp"), "cannot parse port specification", const RuntimeError&);
        CHECK_THROWS_WITH_AS(Port("-1/tcp"), "cannot parse port specification", const RuntimeError&);
        CHECK_THROWS_WITH_AS(Port("22/"), "cannot parse port specification", const RuntimeError&);
        CHECK_THROWS_WITH_AS(Port("/tcp"), "cannot parse port specification", const RuntimeError&);
    }
}

TEST_SUITE_END();
