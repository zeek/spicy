// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <utility>

#include <spicy/rt/global-state.h>

using namespace spicy::rt;

TEST_SUITE_BEGIN("GlobalState");

class TestState {
public:
    TestState() { std::exchange(_prev, detail::__global_state); }

    ~TestState() {
        delete detail::__global_state;
        detail::__global_state = _prev;
    }

private:
    detail::GlobalState* _prev{nullptr};
};

TEST_CASE("createGlobalState") {
    TestState _;
    REQUIRE_EQ(detail::__global_state, nullptr);

    CHECK_NE(detail::createGlobalState(), nullptr);
}


TEST_CASE("globalState") {
    TestState _;
    REQUIRE_EQ(detail::__global_state, nullptr);

    const auto state1 = detail::globalState();
    CHECK_NE(state1, nullptr);
    CHECK_EQ(state1, detail::__global_state);

    const auto state2 = detail::globalState();
    CHECK_EQ(state2, state1);
}

TEST_SUITE_END();
