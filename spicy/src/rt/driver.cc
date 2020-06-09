// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <fstream>
#include <getopt.h>
#include <iostream>

#include <hilti/rt/fmt.h>
#include <hilti/rt/init.h>

#include <spicy/rt/driver.h>

using hilti::rt::Nothing;
using hilti::rt::Result;
using namespace hilti::rt::result;
using hilti::rt::fmt;

using namespace spicy::rt;

inline void Driver::_debug(const std::string_view& msg) {
    if ( ! _enable_debug )
        return;

    HILTI_RT_DEBUG("spicy-driver", msg);
}

void Driver::_debug_stats(const hilti::rt::ValueReference<hilti::rt::Stream>& data) {
    if ( ! _enable_debug )
        return;

    auto pretty_print = [](uint64_t n) {
        if ( n > 1024 * 1024 * 1024 )
            return fmt("%" PRIu64 "G", n / 1024 / 1024 / 1024);
        if ( n > 1024 * 1024 )
            return fmt("%" PRIu64 "M", n / 1024 / 1024);
        if ( n > 1024 )
            return fmt("%" PRIu64 "K", n / 1024);
        return fmt("%" PRIu64, n);
    };

    auto data_begin = data->begin().offset();
    auto data_end = data_begin + data->size();
    auto data_chunks = pretty_print(data->numberChunks());
    auto data_size_cur = pretty_print(data->size());
    auto data_size_total = pretty_print(data_end);

    _debug(fmt("input : size-current=%s size-total=%s chunks-cur=%s offset-head=%" PRIu64 " offset-tail=%" PRIu64,
               data_size_cur, data_size_total, data_chunks, data_begin, data_end));

    auto stats = hilti::rt::memory_statistics();

    auto memory_heap = pretty_print(stats.memory_heap);
    auto num_stacks = pretty_print(stats.num_fibers);
    auto max_stacks = pretty_print(stats.max_fibers);
    auto cached_stacks = pretty_print(stats.cached_fibers);

    _debug(fmt("memory: heap=%s fibers-cur=%s fibers-cached=%s fibers-max=%s", memory_heap, num_stacks, cached_stacks,
               max_stacks));
}

Result<Nothing> Driver::listParsers(std::ostream& out) {
    if ( ! hilti::rt::isInitialized() )
        return Error("runtime not intialized");

    const auto& parsers = spicy::rt::parsers();

    if ( parsers.empty() ) {
        out << "No parsers available.\n";
        return Nothing();
    }

    out << "Available parsers:\n\n";

    for ( const auto& p : parsers ) {
        std::string description;
        std::string mime_types;
        std::string ports;

        if ( p->description.size() )
            description = fmt(" %s", p->description);

        if ( p->mime_types.size() )
            mime_types = fmt(" %s", p->mime_types);

        if ( p->ports.size() )
            ports = fmt(" %s", p->ports);

        out << fmt("  %15s %s%s%s\n", p->name, description, ports, mime_types);
    }

    out << "\n";
    return Nothing();
}

Result<const spicy::rt::Parser*> Driver::lookupParser(const std::string& parser_name) {
    if ( ! hilti::rt::isInitialized() )
        return Error("runtime not intialized");

    const auto& parsers = spicy::rt::parsers();

    if ( parsers.empty() )
        return Error("no parsers available");

    if ( parser_name.empty() ) {
        if ( parsers.size() > 1 )
            return Error("multiple parsers available, need to select one");

        return parsers.front();
    }

    else {
        for ( const auto& i : parsers ) {
            if ( i->name == parser_name )
                return i;
        }

        return Error(fmt("spicy-driver: parser '%s' is not available", parser_name));
    }
}

Result<Nothing> Driver::processInput(const spicy::rt::Parser& parser, std::istream& in, int increment) {
    if ( ! hilti::rt::isInitialized() )
        return Error("runtime not intialized");

    char buffer[4096];
    hilti::rt::ValueReference<hilti::rt::Stream> data;
    std::optional<hilti::rt::Resumable> r;

    _debug_stats(data);

    while ( in.good() && ! in.eof() ) {
        auto len = (increment > 0 ? increment : sizeof(buffer));

        in.read(buffer, len);

        if ( auto n = in.gcount() )
            data->append(hilti::rt::Bytes(buffer, n));

        if ( in.peek() == EOF )
            data->freeze();

        if ( ! r ) {
            _debug(fmt("beginning parsing input (eod=%s)", data->isFrozen()));
            r = parser.parse1(data, {});
        }
        else {
            _debug(fmt("resuming parsing input (eod=%s)", data->isFrozen()));
            r->resume();
        }

        if ( *r ) {
            _debug(fmt("finished parsing input (eod=%s)", data->isFrozen()));
            _debug_stats(data);
            break;
        }
        else {
            _debug("parsing yielded");
            _debug_stats(data);
        }
    }

    return Nothing();
}
