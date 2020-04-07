// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <hilti/rt/logging.h>
#include <hilti/rt/util.h>

using namespace hilti::rt;
using namespace hilti::rt::detail;

#include <cstdlib>
#include <iostream>
#include <utility>

#include <hilti/rt/util.h>

using namespace hilti::rt;

detail::DebugLogger::DebugLogger(std::filesystem::path output) : _path(std::move(output)) {}

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
        auto mode = std::ios::out;

        if ( _path == "/dev/stdout" || _path == "/dev/stderr" )
            mode |= std::ios::app;
        else
            mode |= std::ios::trunc;

        std::ofstream out(_path, mode);

        if ( ! out.is_open() )
            fatalError(fmt("libhilti: cannot open file '%s' for debug output", _path));

        _output = std::move(out);
    }

    auto indent = std::string(i->second * 2, ' ');
    (*_output) << fmt("[%s] %s%s", stream, indent, msg) << std::endl;
}
