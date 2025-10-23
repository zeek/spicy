// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>
#include <unistd.h>

#include <string>

#include <hilti/rt/configuration.h>
#include <hilti/rt/global-state.h>
#include <hilti/rt/init.h>
#include <hilti/rt/profiler.h>

using namespace hilti::rt;

TEST_SUITE_BEGIN("Profiler");

TEST_CASE("measurement") {
    auto old_profiling = hilti::rt::detail::globalState()->profiling_enabled;
    detail::globalState()->profiling_enabled = true;

    uint64_t total = 0;

    for ( int i = 1; i <= 3; i++ ) {
        auto p = profiler::start("xyz");
        ::usleep(10);
        profiler::stop(p);

        auto m = profiler::get("xyz");
        REQUIRE(m);

        CHECK_EQ(m->count, i);
        CHECK(m->time > 0);
        total += (m->time - total);
    }

    auto m = profiler::get("xyz");
    REQUIRE(m);
    CHECK_EQ(m->count, 3);
    CHECK_GT(m->time, 0);
    CHECK_EQ(m->time, total);

    detail::globalState()->profiling_enabled = old_profiling;
}

TEST_SUITE_END();
