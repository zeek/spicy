// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN

#include <doctest/doctest.h>

#include <hilti/rt/configuration.h>
#include <hilti/rt/init.h>

using namespace hilti::rt;

TEST_SUITE_BEGIN("configuration");

TEST_CASE("get/set") {
    // This test needs to be run in a separate executable as updating the configuration
    // after the runtime library is initialized is not supported.
    REQUIRE_FALSE(isInitialized()); // NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)

    auto conf = configuration::get();

    const auto abort_on_exceptions = ! conf.abort_on_exceptions;
    conf.abort_on_exceptions = abort_on_exceptions;

    configuration::set(conf);

    CHECK_EQ(configuration::get().abort_on_exceptions, abort_on_exceptions);
}

TEST_SUITE_END();
