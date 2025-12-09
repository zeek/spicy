// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <exception>
#include <memory>
#include <string>
#include <utility>

#include <hilti/rt/configuration.h>
#include <hilti/rt/exception.h>
#include <hilti/rt/fiber-check-stack.h>
#include <hilti/rt/fiber.h>
#include <hilti/rt/init.h>
#include <hilti/rt/logging.h>
#include <hilti/rt/result.h>

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
        return hilti::rt::Nothing();
    };

    auto r = hilti::rt::fiber::execute(f);
    REQUIRE(r);
    CHECK(r.hasResult());
    CHECK(r.get<hilti::rt::Nothing>() == hilti::rt::Nothing());
    CHECK(x == "Hello from fiber!");
    CHECK(c == "ctordtor");
}

TEST_CASE("reuse-from-cache") {
    hilti::rt::init();

    int x = 0;

    auto f1 = [&](hilti::rt::resumable::Handle* r) {
        x += 1;
        return hilti::rt::Nothing();
    };
    auto r1 = hilti::rt::fiber::execute(f1);
    REQUIRE(r1);
    CHECK(x == 1);

    auto f2 = [&](hilti::rt::resumable::Handle* r) {
        x += 1;
        return hilti::rt::Nothing();
    };
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
    REQUIRE(r.hasResult());
    REQUIRE(r.get<std::string>() == "Hello from fiber!");
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
        return hilti::rt::Nothing();
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
    REQUIRE(r.get<hilti::rt::Nothing>() == hilti::rt::Nothing());
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
    REQUIRE(r.hasResult());
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
        return hilti::rt::Nothing();
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
        return hilti::rt::Nothing();
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

        return hilti::rt::Nothing();
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

    auto f = [&](hilti::rt::resumable::Handle* r) {
        r->yield();
        return hilti::rt::Nothing();
    };

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
    REQUIRE(stats.current == hilti::rt::configuration::get().fiber_cache_size);
    REQUIRE(stats.cached == hilti::rt::configuration::get().fiber_cache_size);
}

TEST_CASE("copy-arg") {
    hilti::rt::init();

    // This mimics how the HILTI codegen generator moves fiber arguments to the heap.
    auto s1 = std::string("string1");
    auto s2 = hilti::rt::ValueReference<std::string>("string2");

    auto args = std::make_tuple(hilti::rt::resumable::detail::copyArg(s1), hilti::rt::resumable::detail::copyArg(s2));
    auto args_on_heap = std::make_shared<decltype(args)>(std::move(args));

    // Check that the copied values have the expected content.
    CHECK_EQ(std::get<0>(*args_on_heap), std::string("string1"));
    CHECK_EQ(std::get<1>(*args_on_heap), std::string("string2"));

    // Check that s1 got actually copied
    CHECK_NE(std::get<0>(*args_on_heap).data(), s1.data());

    // Check that s2 is referring to the same instance (because we specialize ValueReference&<T> that way)
    CHECK_EQ(std::get<1>(*args_on_heap)->data(), s2->data());
}

void X() {}

static int fibo(int i) {
    hilti::rt::detail::checkStack(); // this will eventually throw

    auto* onstack = static_cast<int*>(alloca(512)); // make it fail quicker

    if ( i == 0 )
        return 0;

    if ( i == 1 )
        return 1;

    auto x = fibo(i - 1) + fibo(i - 2);
    onstack[0] = x; // avoid unused variable
    X();            // prevent compiler from removing tail calls
    return x;
}

bool isMacosAsan() {
#if defined(HILTI_HAVE_ASAN) && defined(__APPLE__)
    return true;
#else
    return false;
#endif
}

// This test produces false positives on macos with ASAN.
TEST_CASE("stack-size-check" * doctest::skip(isMacosAsan())) {
    hilti::rt::init();

    auto f = [&](hilti::rt::resumable::Handle* r) {
        fibo(1000000000); // stack won't suffice
        return hilti::rt::Nothing();
    };

    CHECK_THROWS_AS(hilti::rt::fiber::execute(f), hilti::rt::StackSizeExceeded);
}

TEST_CASE("locations") {
    hilti::rt::init();

    hilti::rt::location("global");

    auto f1 = [&](hilti::rt::resumable::Handle* r) {
        hilti::rt::location("f1");
        r->yield();
        CHECK(strcmp(hilti::rt::debug::location(), "f1") == 0);
        return hilti::rt::Nothing();
    };

    auto f2 = [&](hilti::rt::resumable::Handle* r) {
        hilti::rt::location("f2");
        r->yield();
        CHECK(strcmp(hilti::rt::debug::location(), "f2") == 0);
        return hilti::rt::Nothing();
    };

    auto r1 = hilti::rt::fiber::execute(f1);
    auto r2 = hilti::rt::fiber::execute(f2);
    r2.resume();
    r1.resume();
    CHECK(r1);
    CHECK(r2);

    CHECK(strcmp(hilti::rt::debug::location(), "global") == 0);
}

TEST_SUITE_END();
