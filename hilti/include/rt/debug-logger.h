// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <fstream>
#include <map>
#include <optional>
#include <string>

#include <hilti/rt/util.h>

namespace hilti::rt::detail {

/** Logger for runtime debug messages. */
class DebugLogger {
public:
    DebugLogger(std::filesystem::path output);

    void print(const std::string& stream, const std::string& msg);
    void enable(const std::string& streams);

    bool isEnabled(const std::string& stream) { return _streams.find(stream) != _streams.end(); }

    void indent(const std::string& stream) {
        if ( isEnabled(stream) )
            _streams[stream] += 1;
    }

    void dedent(const std::string& stream) {
        if ( isEnabled(stream) )
            _streams[stream] -= 1;
    }

private:
    std::filesystem::path _path;
    std::optional<std::ofstream> _output;
    std::map<std::string, int> _streams;
};

} // namespace hilti::rt::detail
