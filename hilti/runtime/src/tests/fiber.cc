// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <exception>
#include <sstream>

#include <hilti/rt/doctest.h>
#include <hilti/rt/fiber.h>
#include <hilti/rt/init.h>

class TestDtor { //NOLINT
public:
    explicit TestDtor(std::string& c) : c(c) { c += "ctor"; } //NOLINT
    ~TestDtor() { c += "dtor"; }
    std::string& c;
};


TEST_SUITE_BEGIN("fiber");

TEST_CASE("init") { hilti::rt::init(); }

TEST_CASE("execute-void") {
    hilti::rt::init();

    std::string x;
    std::string c;

    auto f = [&](hilti::rt::resumable::Handle* r) {
        TestDtor t(c);
        x = "Hello from fiber!";
    };

    auto r = hilti::rt::fiber::execute(f);
    REQUIRE(r);
    CHECK(x == "Hello from fiber!");
    CHECK(c == "ctordtor");
}

TEST_CASE("reuse-from-cache") {
    hilti::rt::init();

    int x = 0;

    auto f1 = [&](hilti::rt::resumable::Handle* r) { x += 1; };
    auto r1 = hilti::rt::fiber::execute(f1);
    REQUIRE(r1);
    CHECK(x == 1);

    auto f2 = [&](hilti::rt::resumable::Handle* r) { x += 1; };
    auto r2 = hilti::rt::fiber::execute(f2);
    REQUIRE(r2);
    CHECK(x == 2);

    auto stats = hilti::rt::detail::Fiber::statistics();
    REQUIRE(stats.total == 1);
    REQUIRE(stats.current == 1);
    REQUIRE(stats.initialized == 1);
}

TEST_CASE("execute-result") {
    hilti::rt::init();

    std::string x;
    std::string c;

    auto f = [&](hilti::rt::resumable::Handle* r) {
        TestDtor t(c);
        x = "Hello from fiber!";
        return x;
    };

    auto r = hilti::rt::fiber::execute(f);
    REQUIRE(r);
    REQUIRE(x == "Hello from fiber!");
    REQUIRE(r.get<std::string>() == "Hello from fiber!");
    REQUIRE(c == "ctordtor");
}

TEST_CASE("resume-void") {
    hilti::rt::init();

    std::string x;
    std::string c;

    auto f = [&](hilti::rt::resumable::Handle* r) {
        TestDtor t1(c);
        x = "Hello";
        r->yield();
        TestDtor t2(c);
        x += "from";
        r->yield();
        x += "fiber";
        r->yield();
        x += "!";
    };

    auto r = hilti::rt::fiber::execute(f);
    REQUIRE(! r);

    x += " ";
    r.resume();
    REQUIRE(! r);

    x += " ";
    r.resume();
    REQUIRE(! r);

    x += " ";
    r.resume();
    REQUIRE(r);
    REQUIRE(x == "Hello from fiber !");
    REQUIRE(c == "ctorctordtordtor");
}

TEST_CASE("resume-result") {
    hilti::rt::init();

    std::string c;

    auto f = [&](hilti::rt::resumable::Handle* r) {
        TestDtor t(c);
        std::string x;
        x += "Hello";
        r->yield();
        x += " from";
        r->yield();
        x += " fiber";
        r->yield();
        x += "!";
        return x;
    };

    auto r = hilti::rt::fiber::execute(f);
    REQUIRE(! r);

    r.resume();
    REQUIRE(! r);

    r.resume();
    REQUIRE(! r);

    r.resume();
    REQUIRE(r);
    REQUIRE(r.get<std::string>() == "Hello from fiber!");
    REQUIRE(c == "ctordtor");
}

TEST_CASE("exception") {
    hilti::rt::init();

    std::string x;
    std::string c1;
    std::string c2;

    auto f1 = [&](hilti::rt::resumable::Handle* r) {
        TestDtor t(c1);
        x = "Hello";
        throw std::runtime_error("kaputt");
        x += " from fiber!";
    };

    try {
        auto r = hilti::rt::fiber::execute(f1);
        REQUIRE(false);
    } catch ( const std::exception& e ) {
        REQUIRE(e.what() == std::string("kaputt"));
        // REQUIRE(r);
        REQUIRE(x == "Hello");
        REQUIRE(c1 == "ctordtor");
    }

    auto f2 = [&](hilti::rt::resumable::Handle* r) {
        TestDtor t(c2);
        x = "Hello";
        r->yield();
        x += " from";
        throw std::runtime_error("kaputt");
        x += " fiber!";
    };

    auto r2 = hilti::rt::fiber::execute(f2);
    REQUIRE(! r2);

    REQUIRE_THROWS_WITH(r2.resume(), "kaputt");
    REQUIRE(r2);
    REQUIRE(x == "Hello from");
    REQUIRE(c2 == "ctordtor");
}

TEST_CASE("abort") {
    hilti::rt::init();

    std::string x;
    std::string c;

    auto f = [&](hilti::rt::resumable::Handle* r) {
        TestDtor t(c);
        x = "Hello";
        r->yield();
        x += " from fiber!";
    };

    auto r = hilti::rt::fiber::execute(f);
    REQUIRE(! r);
    REQUIRE(x == "Hello");
    REQUIRE(c == "ctor");

    r.abort();
    REQUIRE(r);
    REQUIRE(x == "Hello");
    REQUIRE(c == "ctordtor");
}

TEST_CASE("stats") {
    hilti::rt::init();
    hilti::rt::detail::Fiber::reset(); // reset cache and counters

    auto f = [&](hilti::rt::resumable::Handle* r) { r->yield(); };

    auto r1 = hilti::rt::fiber::execute(f);
    auto r2 = hilti::rt::fiber::execute(f);
    r2.resume();
    REQUIRE(r2);

    auto r3 = hilti::rt::fiber::execute(f);

    r1.resume();
    REQUIRE(r1);

    auto stats = hilti::rt::detail::Fiber::statistics();
    REQUIRE(stats.total == 2);
    REQUIRE(stats.current == 2);
    REQUIRE(stats.cached == 1);
    REQUIRE(stats.max == 2);
    REQUIRE(stats.initialized == 2);

    r3.resume();
    REQUIRE(r3);

    stats = hilti::rt::detail::Fiber::statistics();
    REQUIRE(stats.total == 2);
    REQUIRE(stats.current == 2);
    REQUIRE(stats.cached == 2);
    REQUIRE(stats.max == 2);
    REQUIRE(stats.initialized == 2);
}

TEST_CASE("prime-cache") {
    hilti::rt::init();
    hilti::rt::detail::Fiber::reset(); // reset cache and counters

    auto stats = hilti::rt::detail::Fiber::statistics();
    REQUIRE(stats.current == 0);
    REQUIRE(stats.cached == 0);

    hilti::rt::detail::Fiber::primeCache();

    stats = hilti::rt::detail::Fiber::statistics();
    REQUIRE(stats.current == hilti::rt::detail::Fiber::CacheSize);
    REQUIRE(stats.cached == hilti::rt::detail::Fiber::CacheSize);
}

TEST_SUITE_END();
