// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <getopt.h>

#include <algorithm>
#include <ios>
#include <iostream>
#include <string>
#include <unordered_map>
#include <utility>

#include <hilti/rt/exception.h>
#include <hilti/rt/fmt.h>
#include <hilti/rt/init.h>
#include <hilti/rt/profiler.h>

#include <spicy/rt/driver.h>

using hilti::rt::Nothing;
using hilti::rt::Result;
using namespace hilti::rt::result;
using hilti::rt::fmt;

using namespace spicy::rt;

#ifndef NDEBUG
#define DRIVER_DEBUG(...) debug(__VA_ARGS__)
#define DRIVER_DEBUG_STATS(...) _debugStats(__VA_ARGS__)
#else
#define DRIVER_DEBUG(...)                                                                                              \
    do {                                                                                                               \
    } while ( false )
#define DRIVER_DEBUG_STATS(...)                                                                                        \
    do {                                                                                                               \
    } while ( false )
#endif

HILTI_EXCEPTION_IMPL(InvalidUnitType);

#ifndef NDEBUG
inline static auto pretty_print_number(uint64_t n) {
    if ( n > 1024ULL * 1024 * 1024 )
        return fmt("%" PRIu64 "G", n / 1024 / 1024 / 1024);
    if ( n > 1024ULL * 1024 )
        return fmt("%" PRIu64 "M", n / 1024 / 1024);
    if ( n > 1024 )
        return fmt("%" PRIu64 "K", n / 1024);
    return fmt("%" PRIu64, n);
}
#endif

inline void Driver::debug(const std::string& msg) { HILTI_RT_DEBUG("spicy-driver", msg); }

void Driver::_debugStats(const hilti::rt::ValueReference<hilti::rt::Stream>& data) {
#ifndef NDEBUG
    auto data_begin = data->begin().offset();
    auto data_end = data_begin + data->size();
    auto data_chunks = pretty_print_number(data->numberOfChunks());
    auto data_size_cur = pretty_print_number(data->size());
    auto data_size_total = pretty_print_number(data_end);
#endif

    DRIVER_DEBUG(fmt("input : size-current=%s size-total=%s chunks-cur=%s offset-head=%" PRIu64 " offset-tail=%" PRIu64,
                     data_size_cur, data_size_total, data_chunks, data_begin, data_end));

#ifndef NDEBUG
    auto ru = hilti::rt::resource_usage();
    auto memory_heap = pretty_print_number(ru.memory_heap);
    auto num_stacks = pretty_print_number(ru.num_fibers);
    auto max_stacks = pretty_print_number(ru.max_fibers);
    auto max_stack_size = pretty_print_number(ru.max_fiber_stack_size);
    auto cached_stacks = pretty_print_number(ru.cached_fibers);
#endif

    DRIVER_DEBUG(fmt("memory: heap=%s fibers-cur=%s fibers-cached=%s fibers-max=%s fiber-stack-max=%s", memory_heap,
                     num_stacks, cached_stacks, max_stacks, max_stack_size));
}

void Driver::_debugStats(size_t current_flows, size_t current_connections) {
#ifndef NDEBUG
    auto num_flows = pretty_print_number(current_flows);
    auto total_flows = pretty_print_number(_total_flows);
    auto num_connections = pretty_print_number(current_connections);
    auto total_connections = pretty_print_number(_total_connections);
#endif

    DRIVER_DEBUG(fmt("state: current_flows=%s total_flows=%s current_connections=%s total_connections=%s", num_flows,
                     total_flows, num_connections, total_connections));

#ifndef NDEBUG
    auto stats = hilti::rt::resource_usage();
    auto memory_heap = pretty_print_number(stats.memory_heap);
    auto num_stacks = pretty_print_number(stats.num_fibers);
    auto max_stacks = pretty_print_number(stats.max_fibers);
    auto max_stack_size = pretty_print_number(stats.max_fiber_stack_size);
    auto cached_stacks = pretty_print_number(stats.cached_fibers);
#endif

    DRIVER_DEBUG(fmt("memory  : heap=%s fibers-cur=%s fibers-cached=%s fibers-max=%s fiber-stack-max=%s", memory_heap,
                     num_stacks, cached_stacks, max_stacks, max_stack_size));
}

Result<Nothing> Driver::listParsers(std::ostream& out, bool verbose) {
    if ( ! hilti::rt::isInitialized() )
        return Error("runtime not initialized");

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

    if ( verbose ) {
        bool first = true;
        for ( const auto& [name, parsers] : spicy::rt::parserNames() ) {
            std::set<std::string_view> aliases;

            for ( const auto* p : parsers ) {
                if ( p->name != name )
                    aliases.insert(p->name);
            }

            if ( ! aliases.empty() ) {
                if ( first ) {
                    out << "\nAvailable alias names:\n\n";
                    first = false;
                }

                out << fmt("  %15s -> %s\n", name, hilti::rt::join(aliases, ", "));
            }
        }
    }

    out << "\n";
    return Nothing();
}

Result<spicy::rt::ParsedUnit> Driver::processInput(const spicy::rt::Parser& parser, std::istream& in,
                                                   int increment) try {
    if ( ! hilti::rt::isInitialized() )
        return Error("runtime not initialized");

    if ( ! parser.parse3 )
        return Error(
            fmt("unit type '%s' cannot be used as external entry point because it requires arguments", parser.name));

    char buffer[4096];
    hilti::rt::ValueReference<hilti::rt::Stream> data;
    hilti::rt::Optional<hilti::rt::Resumable> r;

    DRIVER_DEBUG_STATS(data);

    hilti::rt::ValueReference<spicy::rt::ParsedUnit> unit;

    while ( in.good() && ! in.eof() ) {
        auto len = (increment > 0 ? increment : sizeof(buffer));

        in.read(buffer, static_cast<std::streamsize>(len));

        {
            assert(parser.profiler_tags);
            auto profiler = hilti::rt::profiler::start(parser.profiler_tags.prepare_input);

            if ( auto n = in.gcount() )
                data->append(hilti::rt::Bytes(buffer, n));

            if ( in.peek() == EOF )
                data->freeze();
        }
        if ( ! r ) {
            DRIVER_DEBUG(fmt("beginning parsing input (eod=%s)", data->isFrozen()));
            r = parser.parse3(unit, data, {}, {});
        }
        else {
            DRIVER_DEBUG(fmt("resuming parsing input (eod=%s)", data->isFrozen()));
            r->resume();
        }

        if ( *r ) {
            DRIVER_DEBUG(fmt("finished parsing input (eod=%s)", data->isFrozen()));
            DRIVER_DEBUG_STATS(data);
            break;
        }
        else {
            DRIVER_DEBUG("parsing yielded");
            DRIVER_DEBUG_STATS(data);
        }
    }

    return std::move(*unit);
} catch ( const std::exception& e ) {
    return Error(
        fmt("processing failed with exception of type %s: %s", hilti::rt::demangle(typeid(e).name()), e.what()));
} catch ( ... ) {
    return Error(fmt("processing failed with non-standard exception %s",
                     hilti::rt::demangle(typeid(std::current_exception()).name())));
}

void driver::ParsingStateForDriver::debug(const std::string& msg) {
    _driver->debug(hilti::rt::fmt("[%s] %s", _id, msg));
}

void driver::ParsingState::debug(const std::string& msg, size_t size, const char* data) {
    const auto& escaped =
        data ? hilti::rt::escapeBytes(std::string(data, std::min(size_t(40), size))) : fmt("<gap length=%d>", size);
    debug(hilti::rt::fmt("%s: |%s%s|", msg, escaped, size > 40 ? "..." : ""));
}

hilti::rt::Optional<hilti::rt::stream::Offset> driver::ParsingState::finish() {
    switch ( _type ) {
        case driver::ParsingType::Block: break;
        case driver::ParsingType::Stream: {
            _process(0, "", true);
        }
    }

    if ( _resumable && _resumable->hasResult() )
        return _resumable->get<hilti::rt::stream::View>().offset();
    else
        return {};
}

driver::ParsingState::State driver::ParsingState::_process(size_t size, const char* data, bool eod) {
    assert(size == 0 || ! eod);

    if ( ! _parser ) {
        if ( size )
            DRIVER_DEBUG("no parser, further data ignored", size, data);

        return Done;
    }

    if ( _skip ) {
        if ( size )
            DRIVER_DEBUG("skipping, further data ignored", size, data);

        return Done;
    }

    try {
        switch ( _type ) {
            case ParsingType::Block: {
                DRIVER_DEBUG("block", size, data);

                assert(_parser->profiler_tags);
                auto profiler = hilti::rt::profiler::start(_parser->profiler_tags.prepare_block);

                if ( ! _input ) {
                    _input =
                        hilti::rt::reference::make_value<hilti::rt::Stream>(data, size, hilti::rt::stream::NonOwning());

                    if ( ! _parser->parse1 )
                        throw InvalidUnitType(
                            fmt("unit type '%s' cannot be used as external entry point because it requires arguments",
                                _parser->name));
                }
                else {
                    (*_input)->reset();
                    (*_input)->append(data, size, hilti::rt::stream::NonOwning());
                }

                (*_input)->freeze();

                if ( _parser->context_new ) {
                    if ( _context )
                        DRIVER_DEBUG("context was provided");
                    else
                        DRIVER_DEBUG("no context provided");
                }

                hilti::rt::profiler::stop(profiler);

                _resumable = _parser->parse1(*_input, {}, _context);

                if ( ! *_resumable )
                    hilti::rt::internalError("block-based parsing yielded");

                return Done;
            }

            case ParsingType::Stream: {
                if ( _done ) {
                    // Previous parsing has fully finished, we ignore all
                    // further input.
                    if ( size )
                        DRIVER_DEBUG("already finished, further data ignored", size, data);

                    return Done;
                }

                assert(_parser->profiler_tags);
                auto profiler = hilti::rt::profiler::start(_parser->profiler_tags.prepare_stream);

                if ( ! _input ) {
                    // First chunk.
                    DRIVER_DEBUG("first data chunk", size, data);

                    if ( _parser->context_new ) {
                        if ( _context )
                            DRIVER_DEBUG("context was provided");
                        else
                            DRIVER_DEBUG("no context provided");
                    }

                    _input =
                        hilti::rt::reference::make_value<hilti::rt::Stream>(data, size, hilti::rt::stream::NonOwning());
                    if ( eod )
                        (*_input)->freeze();

                    if ( ! _parser->parse1 )
                        throw InvalidUnitType(
                            fmt("unit type '%s' cannot be used as external entry point because it requires arguments",
                                _parser->name));

                    hilti::rt::profiler::stop(profiler);
                    _resumable = _parser->parse1(*_input, {}, _context);
                }

                else {
                    // Resume parsing.
                    assert(_input && _resumable);

                    if ( size )
                        (*_input)->append(data, size, hilti::rt::stream::NonOwning());

                    if ( eod ) {
                        DRIVER_DEBUG("end of data");
                        (*_input)->freeze();
                    }
                    else
                        DRIVER_DEBUG("next data chunk", size, data);

                    hilti::rt::profiler::stop(profiler);
                    _resumable->resume();
                }

                if ( *_resumable ) {
                    // Done parsing.
                    _done = true;
                    DRIVER_DEBUG("parsing finished");
                    return Done;
                }
                else {
                    if ( eod )
                        hilti::rt::internalError("parsing yielded for final data chunk");

                    (*_input)->makeOwning();
                    return Continue;
                }
            }
        }
    } catch ( const hilti::rt::Exception& e ) {
        DRIVER_DEBUG(e.what());
        _done = true;
        throw;
    } catch ( const std::exception& e ) {
        DRIVER_DEBUG(e.what());
        _done = true;
        throw hilti::rt::Exception(e.what());
    } catch ( ... ) {
        const auto* what = "non-standard exception thrown";
        DRIVER_DEBUG(what);
        _done = true;
        throw hilti::rt::Exception(what);
    }

    hilti::rt::cannot_be_reached();
}

Result<hilti::rt::Nothing> Driver::processPreBatchedInput(std::istream& in) {
    std::string magic;
    std::getline(in, magic);

    if ( magic != std::string("!spicy-batch v2") )
        return hilti::rt::result::Error("input is not a v2 Spicy batch file");

    std::unordered_map<std::string, driver::ParsingStateForDriver> flows;
    std::unordered_map<std::string, driver::ConnectionState> connections;

    // Helper to add flows to the map.
    auto create_state = [&](driver::ParsingType type, const std::string& parser_name, const std::string& id,
                            hilti::rt::Optional<std::string> cid, hilti::rt::Optional<UnitContext> context) {
        if ( auto parser = lookupParser(parser_name) ) {
            if ( ! context )
                context = (*parser)->createContext();

            auto x = flows.insert_or_assign(id, driver::ParsingStateForDriver(type, *parser, id, std::move(cid),
                                                                              context, this));
            if ( x.second )
                _total_flows++;

            return std::make_pair(x.first, std::move(context));
        }
        else {
            DRIVER_DEBUG(hilti::rt::fmt("no parser for ID %s, skipping", id));
            return std::make_pair(flows.end(), hilti::rt::Optional<UnitContext>{});
        }
    };

    while ( in.good() && ! in.eof() ) {
        std::string cmd;
        std::getline(in, cmd);
        cmd = hilti::rt::trim(cmd);

        if ( cmd.empty() )
            continue;

        auto m = hilti::rt::split(cmd);
        if ( m[0] == "@begin-flow" ) {
            // @begin-flow <id> <parser> <type>
            if ( m.size() != 4 )
                return hilti::rt::result::Error("unexpected number of argument for @begin-flow");

            auto id = std::string(m[1]);
            auto parser_name = std::string(m[3]);

            driver::ParsingType type;

            if ( m[2] == "stream" )
                type = driver::ParsingType::Stream;
            else if ( m[2] == "block" )
                type = driver::ParsingType::Block;
            else
                return hilti::rt::result::Error(hilti::rt::fmt("unknown session type '%s'", m[2]));


            create_state(type, parser_name, id, {}, {});
        }
        else if ( m[0] == "@begin-conn" ) {
            // @begin-conn <conn-id> <type> <orig-id> <orig-parser> <resp-id> <resp-parser>
            if ( m.size() != 7 )
                return hilti::rt::result::Error("unexpected number of argument for @begin-conn");

            auto cid = std::string(m[1]);
            auto orig_id = std::string(m[3]);
            auto orig_parser_name = std::string(m[4]);
            auto resp_id = std::string(m[5]);
            auto resp_parser_name = std::string(m[6]);

            driver::ParsingType type;

            if ( m[2] == "stream" )
                type = driver::ParsingType::Stream;
            else if ( m[2] == "block" )
                type = driver::ParsingType::Block;
            else
                return hilti::rt::result::Error(hilti::rt::fmt("unknown session type '%s'", m[2]));

            if ( connections.contains(cid) ) {
                // already exists, ignore
                DRIVER_DEBUG(hilti::rt::fmt("connection %s exists, skipping", cid));
                continue;
            }

            driver::ParsingStateForDriver* orig_state = nullptr;
            driver::ParsingStateForDriver* resp_state = nullptr;

            hilti::rt::Optional<UnitContext> context;

            if ( auto [x, ctx] = create_state(type, orig_parser_name, orig_id, cid, context); x != flows.end() ) {
                orig_state = &x->second;
                context = std::move(ctx);
            }

            if ( auto [x, ctx] = create_state(type, resp_parser_name, resp_id, cid, std::move(context));
                 x != flows.end() )
                resp_state = &x->second;

            if ( ! (orig_state || resp_state) ) {
                // cannot get parsers, ignore
                flows.erase(orig_id);
                flows.erase(resp_id);
                continue;
            }

            connections[cid] = driver::ConnectionState{.orig_id = std::move(orig_id),
                                                       .resp_id = std::move(resp_id),
                                                       .orig_state = orig_state,
                                                       .resp_state = resp_state};
            _total_connections++;
        }
        else if ( m[0] == "@data" ) {
            // @data <id> <size>
            // [data]\n
            if ( m.size() != 3 )
                return hilti::rt::result::Error("unexpected number of argument for @data");

            auto id = std::string(m[1]);
            auto size = std::stoul(std::string(m[2]));

            std::string data(size, {});
            in.read(data.data(), static_cast<std::streamsize>(size));
            in.get(); // Eat newline.

            if ( in.eof() || in.fail() )
                return hilti::rt::result::Error("premature end of @data");

            auto s = flows.find(id);
            if ( s != flows.end() ) {
                try {
                    s->second.process(size, data.data());
                } catch ( const hilti::rt::Exception& e ) {
                    std::cout << hilti::rt::fmt("error for ID %s: %s\n", id, e.what());
                }
            }
        }
        else if ( m[0] == "@gap" ) {
            // @gap <id> <size>
            if ( m.size() != 3 )
                return hilti::rt::result::Error("unexpected number of argument for @gap");

            auto id = std::string(m[1]);
            auto size = std::stoul(std::string(m[2]));

            auto s = flows.find(id);
            if ( s != flows.end() ) {
                try {
                    s->second.process(size, nullptr);
                } catch ( const hilti::rt::Exception& e ) {
                    std::cout << hilti::rt::fmt("error for ID %s: %s\n", id, e.what());
                }
            }
        }
        else if ( m[0] == "@end-flow" ) {
            // @end-flow <id>
            if ( m.size() != 2 )
                return hilti::rt::result::Error("unexpected number of argument for @end-flow");

            auto id = std::string(m[1]);

            auto s = flows.find(id);
            if ( s != flows.end() ) {
                try {
                    s->second.finish();
                } catch ( const hilti::rt::Exception& e ) {
                    std::cout << hilti::rt::fmt("error for ID %s: %s\n", id, e.what());
                }

                flows.erase(s);
                DRIVER_DEBUG_STATS(flows.size(), connections.size());
            }
        }
        else if ( m[0] == "@end-conn" ) {
            // @end-conn <cid>
            if ( m.size() != 2 )
                return hilti::rt::result::Error("unexpected number of argument for @end-conn");

            auto cid = std::string(m[1]);

            if ( auto s = connections.find(cid); s != connections.end() ) {
                try {
                    if ( s->second.orig_state )
                        s->second.orig_state->finish();
                } catch ( const hilti::rt::Exception& e ) {
                    std::cout << hilti::rt::fmt("error for ID %s: %s\n", s->second.orig_id, e.what());
                }

                try {
                    if ( s->second.resp_state )
                        s->second.resp_state->finish();
                } catch ( const hilti::rt::Exception& e ) {
                    std::cout << hilti::rt::fmt("error for ID %s: %s\n", s->second.resp_id, e.what());
                }

                flows.erase(s->second.orig_id);
                flows.erase(s->second.resp_id);
                connections.erase(s);
                DRIVER_DEBUG_STATS(flows.size(), connections.size());
            }
        }
        else
            return hilti::rt::result::Error(hilti::rt::fmt("unknown command '%s'", m[0]));
    }


    DRIVER_DEBUG_STATS(flows.size(), connections.size());

    return hilti::rt::Nothing();
}
