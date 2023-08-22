// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#include <hilti/rt/doctest.h>
#include <hilti/rt/init.h>
#include <hilti/rt/types/barrier.h>
#include "exception.h"

using namespace hilti::rt;

TEST_SUITE_BEGIN("Barrier");

TEST_CASE("construct") {
    auto b1 = Barrier(0);
    CHECK(b1.isReleased());
    CHECK(b1);
    CHECK(! b1.isAborted());
    CHECK(b1.isReleased());

    auto b2 = Barrier(3);
    CHECK(! b2.isReleased());
    CHECK(! b2);
    CHECK(! b2.isAborted());
    CHECK(! b2.isReleased());
}

TEST_CASE("three-parties") {
    hilti::rt::init();

    std::string x;
    hilti::rt::Barrier b(3);

    auto p1 = [&](hilti::rt::resumable::Handle* r) {
        x += "a";
        b.arrive_and_wait();
        CHECK(b.isReleased());
        x += "b";
        return hilti::rt::Nothing();
    };

    auto p2 = [&](hilti::rt::resumable::Handle* r) {
        x += "c";
        b.arrive_and_wait();
        CHECK(b.isReleased());
        x += "d";
        return hilti::rt::Nothing();
    };

    auto p3 = [&](hilti::rt::resumable::Handle* r) {
        x += "e";
        b.arrive_and_wait();
        CHECK(b.isReleased());
        x += "f";
        return hilti::rt::Nothing();
    };

    auto r1 = hilti::rt::fiber::execute(p1);
    REQUIRE(! r1);
    CHECK(r1.atBarrier());
    CHECK(! b.isReleased());

    auto r2 = hilti::rt::fiber::execute(p2);
    REQUIRE(! r2);
    CHECK(r2.atBarrier());
    CHECK(! b.isReleased());

    auto r3 = hilti::rt::fiber::execute(p3);
    REQUIRE(r3);
    CHECK(! r3.atBarrier());
    CHECK(b.isReleased());

    r1.resume();
    REQUIRE(r1);
    CHECK(! r1.atBarrier());
    CHECK(b.isReleased());

    r2.resume();
    REQUIRE(r2);
    CHECK(! r2.atBarrier());
    CHECK(b.isReleased());

    CHECK_NOTHROW(b.wait());

    CHECK_EQ(x, "acefbd");
}

TEST_CASE("abort") {
    hilti::rt::init();

    SUBCASE("abort during wait") {
        hilti::rt::Barrier b(3);
        auto p = [&](hilti::rt::resumable::Handle* r) {
            b.arrive_and_wait();
            b.arrive_and_wait();
            return hilti::rt::Nothing();
        };

        auto r = hilti::rt::fiber::execute(p);
        REQUIRE(! r);
        CHECK(r.atBarrier());
        CHECK(! b.isReleased());
        CHECK(! b.isAborted());

        r.resume();
        REQUIRE(! r);
        CHECK(r.atBarrier());
        CHECK(! b.isReleased());
        CHECK(! b.isAborted());

        b.abort();
        CHECK_THROWS_AS(b.wait(), BarrierAborted);

        CHECK_THROWS_AS(r.resume(), BarrierAborted);
        REQUIRE(r);
        CHECK(! r.atBarrier());
        CHECK(! b.isReleased());
        CHECK(b.isAborted());

        CHECK_THROWS_AS(b.wait(), BarrierAborted);
    }

    SUBCASE("abort after release") {
        hilti::rt::Barrier b(1);
        b.arrive();
        CHECK(b.isReleased());

        CHECK_NOTHROW(b.wait());
    }
}

TEST_SUITE_END();
