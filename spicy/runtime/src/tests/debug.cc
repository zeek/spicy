// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#include <hilti/rt/doctest.h>
#include <hilti/rt/global-state.h>
#include <hilti/rt/init.h>
#include <hilti/rt/logging.h>

#include <spicy/rt/debug.h>

using namespace spicy::rt;

TEST_SUITE_BEGIN("Debug");

TEST_CASE("wantVerbose") {
    SUBCASE("no runtime") {
        hilti::rt::done();
        CHECK_FALSE(debug::wantVerbose());
    }

    SUBCASE("disabled") {
        // Bootstrap a clean runtime.
        hilti::rt::done();
        hilti::rt::init();

        const auto& logger = hilti::rt::detail::globalState()->debug_logger;
        REQUIRE(logger);
        REQUIRE_FALSE(logger->isEnabled("spicy-verbose"));

        CHECK_FALSE(debug::wantVerbose());
    }

    SUBCASE("enabled") {
        // Bootstrap a clean runtime.
        hilti::rt::done();
        hilti::rt::init();

        const auto& logger = hilti::rt::detail::globalState()->debug_logger;
        REQUIRE(logger);
        logger->enable("spicy-verbose");
        REQUIRE(logger->isEnabled("spicy-verbose"));

        CHECK(debug::wantVerbose());
    }
}

TEST_SUITE_END();
