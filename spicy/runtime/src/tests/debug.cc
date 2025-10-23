// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <hilti/rt/configuration.h>
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
        REQUIRE(! logger);

        CHECK_FALSE(debug::wantVerbose());
    }

    SUBCASE("enabled") {
        // Bootstrap a clean runtime.
        hilti::rt::done();

        auto config = hilti::rt::configuration::get();
        config.debug_streams = "spicy-verbose";
        hilti::rt::configuration::set(std::move(config));

        hilti::rt::init();
        const auto& logger = hilti::rt::detail::globalState()->debug_logger;
        REQUIRE(logger);
        REQUIRE(logger->isEnabled("spicy-verbose"));

        CHECK(debug::wantVerbose());
    }
}

TEST_SUITE_END();
