// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

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
    CHECK_EQ(detail::__global_state->debug_logger, nullptr);
    CHECK_NE(detail::__global_state->master_context, nullptr);
    CHECK_NE(configuration::detail::__configuration, nullptr);
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

TEST_CASE("registerModule") {
    const auto initial_size = detail::globalState()->hilti_modules.size();

    SUBCASE("IDs of registered modules are unique") {
        detail::registerModule({.name = "foo", .id = 1});
        CHECK_EQ(detail::globalState()->hilti_modules.size(), initial_size + 1);

        detail::registerModule({.name = "foo", .id = 1});
        CHECK_EQ(detail::globalState()->hilti_modules.size(), initial_size + 1);

        detail::registerModule({.name = "foo", .id = 2});
        CHECK_EQ(detail::globalState()->hilti_modules.size(), initial_size + 2);
    }

    SUBCASE("can register multiple modules from same linker scope") {
        detail::registerModule({.name = "foo", .id = 4});
        detail::registerModule({.name = "bar", .id = 4});

        CHECK_EQ(detail::globalState()->hilti_modules.size(), initial_size + 2);
    }
}
