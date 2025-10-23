// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>
#include <unistd.h>

#include <cstdlib>
#include <fstream>
#include <string>

#include <hilti/rt/debug-logger.h>
#include <hilti/rt/filesystem.h>
#include <hilti/rt/test/utils.h>
#include <hilti/rt/util.h>

using namespace hilti::rt;
using namespace hilti::rt::test;

namespace std {
ostream& operator<<(ostream& stream, const std::vector<std::string>& xs) {
    return stream << "[" << join(xs, ", ") << "]";
}
} // namespace std

TEST_SUITE_BEGIN("DebugLogger");

TEST_CASE("enable") {
    auto output = TemporaryFile();
    auto logger = detail::DebugLogger(output.path());

    CHECK_FALSE(logger.isEnabled("FOO"));

    logger.enable("FOO");

    CHECK(logger.isEnabled("FOO"));
}

TEST_CASE("indent") {
    auto output = TemporaryFile();
    auto logger = detail::DebugLogger(output.path());

    std::vector<std::string> lines;

    // This indent call has no effect since the stream is not enabled.
    logger.indent("FOO");
    logger.print("FOO", "foo");
    CHECK_EQ(output.lines(), lines);

    logger.enable("FOO");
    logger.indent("FOO");
    logger.print("FOO", "foo");
    lines.emplace_back("[FOO]   foo"); // Indent is a multiple of 2.
    CHECK_EQ(output.lines(), lines);

    logger.enable("BAR");
    logger.print("BAR", "bar");
    lines.emplace_back("[BAR] bar"); // Line was not indented.
    CHECK_EQ(output.lines(), lines);
}

TEST_CASE("dedent") {
    auto output = TemporaryFile();
    auto logger = detail::DebugLogger(output.path());

    std::vector<std::string> lines;

    // This dedent call has no effect since the stream is not enabled.
    logger.dedent("FOO");
    logger.print("FOO", "foo");
    CHECK_EQ(output.lines(), lines);

    logger.enable("FOO");
    logger.dedent("FOO"); // Dedent of unindented line has no effect.
    logger.print("FOO", "foo");
    lines.emplace_back("[FOO] foo");
    CHECK_EQ(output.lines(), lines);

    logger.enable("BAR");
    logger.indent("BAR");
    logger.print("BAR", "bar");
    lines.emplace_back("[BAR]   bar"); // Indent is a multiple of 2.
    CHECK_EQ(output.lines(), lines);

    logger.dedent("BAR");
    logger.print("BAR", "bar");
    lines.emplace_back("[BAR]  bar");
}

TEST_CASE("print") {
    auto output = TemporaryFile();
    auto logger = detail::DebugLogger(output.path());
    logger.enable("FOO");

    REQUIRE(output.lines().empty());

    logger.print("FOO", "foo");
    CHECK_EQ(output.lines(), std::vector<std::string>({"[FOO] foo"}));

    logger.print("BAR", "bar");
    CHECK_EQ(output.lines(), std::vector<std::string>({"[FOO] foo"}));

    logger.enable("BAR");
    logger.print("BAR", "bar");
    CHECK_EQ(output.lines(), std::vector<std::string>({"[FOO] foo", "[BAR] bar"}));
}

TEST_SUITE_END();
