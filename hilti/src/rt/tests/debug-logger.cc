// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>
#include <unistd.h>

#include <cstdlib>
#include <fstream>
#include <string>

#include <hilti/rt/debug-logger.h>
#include <hilti/rt/util.h>

using namespace hilti::rt;

namespace std {
ostream& operator<<(ostream& stream, const std::vector<std::string>& xs) {
    return stream << "[" << join(xs, ", ") << "]";
}
} // namespace std

class Tmpfile {
public:
    explicit Tmpfile() {
        std::filesystem::path tmpdir = std::getenv("TMPDIR") ? std::getenv("TMPDIR") : "/tmp";
        if ( tmpdir.empty() )
            tmpdir = "/tmp";

        std::string path = tmpdir / "debug-logger-tests-XXXXXX";

        auto fd = mkstemp(path.data());
        REQUIRE_NE(fd, -1);
        ::close(fd);

        _path = path;
    }

    std::vector<std::string> lines() const {
        auto file = std::ifstream(_path);

        std::string line;
        std::vector<std::string> lines;
        while ( std::getline(file, line) )
            lines.push_back(line);

        return lines;
    }

    ~Tmpfile() { REQUIRE_EQ(::unlink(_path.c_str()), 0); }

    std::filesystem::path _path;
};

TEST_SUITE_BEGIN("DebugLogger");

TEST_CASE("enable") {
    auto output = Tmpfile();
    auto logger = detail::DebugLogger(output._path);

    CHECK_FALSE(logger.isEnabled("FOO"));

    logger.enable("FOO");

    CHECK(logger.isEnabled("FOO"));
}

TEST_CASE("indent") {
    auto output = Tmpfile();
    auto logger = detail::DebugLogger(output._path);

    std::vector<std::string> lines;

    // This indent call has no effect since the stream is not enabled.
    logger.indent("FOO");
    logger.print("FOO", "foo");
    CHECK_EQ(output.lines(), lines);

    logger.enable("FOO");
    logger.indent("FOO");
    logger.print("FOO", "foo");
    lines.push_back("[FOO]   foo"); // Indent is a multiple of 2.
    CHECK_EQ(output.lines(), lines);

    logger.enable("BAR");
    logger.print("BAR", "bar");
    lines.push_back("[BAR] bar"); // Line was not indented.
    CHECK_EQ(output.lines(), lines);
}

TEST_CASE("dedent") {
    auto output = Tmpfile();
    auto logger = detail::DebugLogger(output._path);

    std::vector<std::string> lines;

    // This dedent call has no effect since the stream is not enabled.
    logger.dedent("FOO");
    logger.print("FOO", "foo");
    CHECK_EQ(output.lines(), lines);

    logger.enable("FOO");
    logger.dedent("FOO"); // Dedent of unindented line has no effect.
    logger.print("FOO", "foo");
    lines.push_back("[FOO] foo");
    CHECK_EQ(output.lines(), lines);

    logger.enable("BAR");
    logger.indent("BAR");
    logger.print("BAR", "bar");
    lines.push_back("[BAR]   bar"); // Indent is a multiple of 2.
    CHECK_EQ(output.lines(), lines);

    logger.dedent("BAR");
    logger.print("BAR", "bar");
    lines.push_back("[BAR]  bar");
}

TEST_CASE("print") {
    auto output = Tmpfile();
    auto logger = detail::DebugLogger(output._path);
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
