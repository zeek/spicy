// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/rt/logging.h>
#include <hilti/rt/util.h>

using namespace hilti::rt;
using namespace hilti::rt::detail;

#include <cstdlib>
#include <iostream>
#include <utility>


using namespace hilti::rt;

detail::DebugLogger::DebugLogger(hilti::rt::filesystem::path output) : _path(std::move(output)) {}

void detail::DebugLogger::enable(const std::string& streams) {
    for ( auto s : split(streams, ":") )
        _streams[std::string(trim(s))] = 0;
}

void detail::DebugLogger::print(const std::string& stream, const std::string& msg) {
    if ( _path.empty() )
        return;

    auto i = _streams.find(stream);
    if ( i == _streams.end() )
        return;

    if ( ! _output ) {
        if ( _path == "/dev/stdout" )
            _output = &std::cout;
        else if ( _path == "/dev/stderr" )
            _output = &std::cerr;
        else {
            _output_file = std::make_unique<std::ofstream>(_path, std::ios::out | std::ios::trunc);
            if ( ! _output_file->is_open() )
                warning(fmt("libhilti: cannot open file '%s' for debug output", _path));

            _output = _output_file.get();
        }
    }

    auto indent = std::string(i->second * 2, ' ');
    (*_output) << fmt("[%s] %s%s", stream, indent, msg) << std::endl;
}
