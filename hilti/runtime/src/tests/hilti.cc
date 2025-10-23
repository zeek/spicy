// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <memory>
#include <utility>

#include <hilti/rt/configuration.h>
#include <hilti/rt/global-state.h>
#include <hilti/rt/hilti.h>
#include <hilti/rt/types/bytes.h>
#include <hilti/rt/types/real.h>

using namespace hilti::rt;
using namespace hilti::rt::bytes::literals;

// RAII helper to set the global `Configuration`'s `cout` stream.
class TestCout {
public:
    TestCout() : _prev(std::make_unique<Configuration>()) {
        _prev->cout = _cout;
        std::swap(configuration::detail::__configuration, _prev);
    }

    ~TestCout() { configuration::detail::__configuration = std::move(_prev); }

    auto str() const { return _cout.str(); }

private:
    std::stringstream _cout;
    std::unique_ptr<Configuration> _prev;
};

TEST_SUITE_BEGIN("hilti");

TEST_CASE("print") {
    SUBCASE("w/ newline") {
        TestCout cout;
        print("\x00\x01"_b, nullptr, true);
        print(0.5, nullptr, true);
        CHECK_EQ(cout.str(), "\\x00\\x01\n0.5\n");
    }

    SUBCASE("w/o newline") {
        TestCout cout;
        print("\x00\x01"_b, nullptr, false);
        print(0.5, nullptr, false);
        CHECK_EQ(cout.str(), "\\x00\\x010.5");
    }
}

TEST_SUITE_END();
