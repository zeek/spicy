// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <hilti/rt/doctest.h>
#include <hilti/rt/global-state.h>
#include <hilti/rt/init.h>

using namespace hilti::rt;

TEST_SUITE_BEGIN("Init");

TEST_CASE("done") {
    init(); // Noop if already initialized.
    REQUIRE_NE(detail::__global_state, nullptr);
    REQUIRE_NE(context::detail::get(), nullptr);

    done();

    CHECK_EQ(detail::__global_state, nullptr);
    // TODO(bbannier): Cannot check this since it asserts a non-nil value internally.
    // CHECK_EQ(context::detail::get(), nullptr);
}

TEST_CASE("init") {
    // Make sure the runtime is stopped.
    if ( detail::__global_state )
        done();

    init();

    CHECK_NE(context::detail::get(), nullptr);

    REQUIRE_NE(detail::__global_state, nullptr);
    CHECK_NE(detail::__global_state->debug_logger, nullptr);
    CHECK_NE(detail::__global_state->master_context, nullptr);
    CHECK_NE(detail::__global_state->configuration, nullptr);
    CHECK(detail::__global_state->runtime_is_initialized);
}

TEST_CASE("isInitialized") {
    // Make sure the runtime is stopped.
    if ( detail::__global_state )
        done();

    REQUIRE_FALSE(isInitialized());

    init();

    CHECK(isInitialized());
}

TEST_SUITE_END();
