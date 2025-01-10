// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <fstream>
#include <map>
#include <memory>
#include <string_view>

#include <hilti/rt/filesystem.h>
#include <hilti/rt/util.h>

namespace hilti::rt::detail {

/** Logger for runtime debug messages. */
class DebugLogger {
public:
    DebugLogger(hilti::rt::filesystem::path output);

    void print(std::string_view stream, std::string_view msg);
    void enable(std::string_view streams);

    bool isEnabled(std::string_view stream) { return _streams.find(stream) != _streams.end(); }

    void indent(std::string_view stream) {
        if ( auto s = _streams.find(stream); s != _streams.end() ) {
            auto& indent = s->second;
            indent += 1;
        }
    }

    void dedent(std::string_view stream) {
        if ( auto s = _streams.find(stream); s != _streams.end() ) {
            auto& indent = s->second;
            if ( indent > 0 )
                indent -= 1;
        }
    }

private:
    hilti::rt::filesystem::path _path;
    std::ostream* _output = nullptr;
    std::unique_ptr<std::ofstream> _output_file;
    std::map<std::string_view, integer::safe<uint64_t>> _streams;
};

} // namespace hilti::rt::detail
