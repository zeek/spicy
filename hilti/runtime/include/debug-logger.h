// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <fstream>
#include <map>
#include <memory>
#include <optional>
#include <string>

#include <hilti/rt/filesystem.h>
#include <hilti/rt/util.h>

namespace hilti::rt::detail {

/** Logger for runtime debug messages. */
class DebugLogger {
public:
    DebugLogger(hilti::rt::filesystem::path output);

    void print(const std::string& stream, const std::string& msg);
    void enable(const std::string& streams);

    bool isEnabled(const std::string& stream) { return _streams.find(stream) != _streams.end(); }

    void indent(const std::string& stream) {
        if ( isEnabled(stream) )
            _streams[stream] += 1;
    }

    void dedent(const std::string& stream) {
        if ( isEnabled(stream) ) {
            auto& indent = _streams[stream];

            if ( indent > 0 )
                indent -= 1;
        }
    }

private:
    hilti::rt::filesystem::path _path;
    std::ostream* _output = nullptr;
    std::unique_ptr<std::ofstream> _output_file;
    std::map<std::string, integer::safe<uint64_t>> _streams;
};

} // namespace hilti::rt::detail
