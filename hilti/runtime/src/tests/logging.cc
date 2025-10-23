// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <memory>
#include <string>
#include <vector>

#include <hilti/rt/context.h>
#include <hilti/rt/debug-logger.h>
#include <hilti/rt/global-state.h>
#include <hilti/rt/init.h>
#include <hilti/rt/logging.h>
#include <hilti/rt/test/utils.h>

using namespace hilti::rt;
using namespace hilti::rt::test;

TEST_SUITE_BEGIN("Logging");

// RAII helper to maintain global debug logger.
class TestLogger {
public:
    TestLogger() : _prev(std::make_unique<detail::DebugLogger>(_file.path())) {
        init(); // Noop if already initialized.
        std::swap(_prev, detail::globalState()->debug_logger);
    }

    ~TestLogger() { detail::globalState()->debug_logger = std::move(_prev); }

    auto lines() const { return _file.lines(); }

private:
    TemporaryFile _file;
    std::unique_ptr<detail::DebugLogger> _prev;
};

TEST_CASE("debug::isEnabled") {
    TestLogger log;
    CHECK_FALSE(debug::isEnabled("foo"));
    CHECK_FALSE(debug::isEnabled("bar"));

    detail::globalState()->debug_logger->enable("foo");
    CHECK(debug::isEnabled("foo"));
    CHECK_FALSE(debug::isEnabled("bar"));

    detail::globalState()->debug_logger->enable("bar");
    CHECK(debug::isEnabled("foo"));
    CHECK(debug::isEnabled("bar"));
}

TEST_CASE("debug::dedent") {
    TestLogger log;
    detail::globalState()->debug_logger->enable("foo");

    std::vector<std::string> expected;

    debug::dedent("foo");
    HILTI_RT_DEBUG("foo", "test1");
    expected.emplace_back("[foo] test1");
    CHECK_EQ(log.lines(), expected);

    debug::indent("foo");
    HILTI_RT_DEBUG("foo", "test1");
    expected.emplace_back("[foo]   test1");
    CHECK_EQ(log.lines(), expected);

    debug::dedent("foo");
    HILTI_RT_DEBUG("foo", "test1");
    expected.emplace_back("[foo] test1");
    CHECK_EQ(log.lines(), expected);
}

TEST_CASE("debug::indent") {
    TestLogger log;
    detail::globalState()->debug_logger->enable("foo");

    std::vector<std::string> expected;

    debug::indent("foo");
    HILTI_RT_DEBUG("foo", "test1");
    expected.emplace_back("[foo]   test1");
    CHECK_EQ(log.lines(), expected);

    debug::indent("foo");
    HILTI_RT_DEBUG("foo", "test1");
    expected.emplace_back("[foo]     test1");
    CHECK_EQ(log.lines(), expected);
}

TEST_CASE("debug::location") {
    Context context(0);
    TestContext _(&context);

    CHECK_EQ(debug::location(), nullptr);

    REQUIRE(context::detail::current());
    const auto* const source_location = "foo/bar.h";
    debug::setLocation(source_location);

    CHECK_EQ(debug::location(), source_location);
    debug::setLocation(nullptr);
}

TEST_CASE("HILTI_RT_DEBUG") {
    TestLogger log;

    std::vector<std::string> expected;

    HILTI_RT_DEBUG("foo", "test1");
    CHECK(log.lines().empty());
    // Nothing logged since stream not enabled.

    detail::globalState()->debug_logger->enable("foo");
    HILTI_RT_DEBUG("foo", "test2");
    expected.emplace_back("[foo] test2");
    CHECK_EQ(log.lines(), expected);
}

TEST_CASE("warning") {
    CaptureIO cerr(std::cerr);
    warning("foo");
    CHECK_EQ(cerr.str(), "[libhilti] Warning: foo\n");
}

TEST_SUITE_END();
