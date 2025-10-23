// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <string>

#include <hilti/rt/global-state.h>
#include <hilti/rt/init.h>

using namespace hilti::rt;

TEST_SUITE_BEGIN("GlobalState");

TEST_CASE("createGlobalState") {
    done(); // Clear any existing global state.
    REQUIRE_EQ(detail::__global_state, nullptr);

    const auto* globalState = detail::createGlobalState();
    CHECK_NE(globalState, nullptr);
    CHECK_EQ(globalState, detail::__global_state);
}

TEST_CASE("globalState") {
    done(); // Clear any existing global state.
    REQUIRE_EQ(detail::__global_state, nullptr);

    // `globalState` creates a global state.
    const auto* globalState = detail::globalState();
    CHECK_NE(globalState, nullptr);
    CHECK_EQ(globalState, detail::__global_state);

    // `globalState` is idempotent.
    CHECK_EQ(detail::globalState(), globalState);
}

TEST_CASE("initModuleGlobals/hiltiGlobals/moduleGlobals") {
    // TODO(bbannier): Cannot test behavior with unset global state
    // since called functions assert it being not nil internally.

    init(); // Noop if already initialized.

    CHECK(detail::hiltiGlobals().empty());

    unsigned int idx = -1; // Controlled use of overflow below.

    detail::registerModule({.name = "1", .id = 1});
    detail::initModuleGlobals<int>(++idx);

    REQUIRE_EQ(detail::hiltiGlobals().size(), 1U);
    CHECK_NE(detail::hiltiGlobals().back(), nullptr);
    CHECK_EQ(detail::hiltiGlobals().back(), detail::moduleGlobals<int>(idx));
    REQUIRE(detail::moduleGlobals<int>(idx));
    CHECK_EQ(*detail::moduleGlobals<int>(idx), 0U);

    detail::registerModule({.name = "2", .id = 2});
    detail::initModuleGlobals<int>(++idx);

    REQUIRE_EQ(detail::hiltiGlobals().size(), 2U);
    REQUIRE_NE(detail::hiltiGlobals().back(), nullptr);
    CHECK_EQ(detail::hiltiGlobals().back(), detail::moduleGlobals<int>(idx));
    CHECK_NE(detail::moduleGlobals<int>(idx - 1), detail::moduleGlobals<int>(idx));
}

TEST_SUITE_END();
