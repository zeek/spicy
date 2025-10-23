// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <cstddef>

#include <hilti/rt/context.h>
#include <hilti/rt/init.h>
#include <hilti/rt/test/utils.h>
#include <hilti/rt/threading.h>

using namespace hilti::rt;
using namespace hilti::rt::test;

TEST_SUITE_BEGIN("Context");

TEST_CASE("cookie") {
    Context context(42);
    TestContext _(&context);

    CHECK_EQ(context::cookie(), nullptr);

    void* const cookie = reinterpret_cast<void*>(0xDEADBEEF);

    context.cookie = cookie;
    CHECK_EQ(context::cookie(), cookie);

    context::clearCookie();
    CHECK_EQ(context::cookie(), nullptr);

    context::saveCookie(cookie);
    CHECK_EQ(context::cookie(), cookie);
}

TEST_CASE("CookieSetter") {
    Context context(vthread::Master);
    TestContext _(&context);

    REQUIRE_EQ(context::cookie(), nullptr);

    {
        void* const cookie = reinterpret_cast<void*>(0xDEADBEEF);
        context::CookieSetter _(cookie);
        CHECK_EQ(context::cookie(), cookie);
    }

    CHECK_EQ(context::cookie(), nullptr);
}

TEST_CASE("execute") {
    init(); // Noop if already initialized.

    size_t count = 0;

    CHECK_EQ(context::execute(
                 [&count](int a, int b) {
                     ++count;
                     return a + b;
                 },
                 40, 2)
                 .get<int>(),
             42);

    CHECK_EQ(count, 1U); // Function was executed exactly once.
}

TEST_SUITE_END();
