// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <doctest/doctest.h>
#include <unistd.h>

#include <cstdlib>
#include <fstream>
#include <sstream>
#include <streambuf>
#include <string>
#include <vector>

#include <hilti/rt/context.h>
#include <hilti/rt/filesystem.h>
#include <hilti/rt/logging.h>
#include <hilti/rt/util.h>

namespace hilti::rt::test {
// RAII helper to maintain a temporary file
class TemporaryFile {
public:
    explicit TemporaryFile() {
        std::string path = hilti::rt::filesystem::temp_directory_path() / "hilti-rt-tests-XXXXXX";

        auto fd = ::mkstemp(path.data());
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

    const auto& path() const { return _path; }

    ~TemporaryFile() {
        std::error_code ec;
        auto exists = hilti::rt::filesystem::exists(_path, ec);

        if ( ec )
            fatalError(fmt("failed to check whether %s exists: %s", _path, ec));

        if ( exists )
            hilti::rt::filesystem::remove_all(_path, ec); // Swallow any error from removal.
    }

private:
    hilti::rt::filesystem::path _path;
};

// RAII helper to redirect output.
class CaptureIO {
public:
    CaptureIO(std::ostream& stream) : _old(stream.rdbuf(_buffer.rdbuf())), _stream(&stream) {}
    ~CaptureIO() { _stream->rdbuf(_old); }

    auto str() const { return _buffer.str(); }

private:
    std::stringstream _buffer = std::stringstream{};
    std::streambuf* _old = nullptr;
    std::ostream* _stream = nullptr;
};

// RAII helper to maintain a controlled context in tests.
class TestContext {
public:
    TestContext(Context* current) {
        _prev = context::detail::current();
        context::detail::current() = current;
    }

    ~TestContext() { context::detail::current() = _prev; }

private:
    Context* _prev = nullptr;
};

} // namespace hilti::rt::test
