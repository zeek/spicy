// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <utility>

#include <hilti/base/logger.h>
#include <hilti/base/util.h>

using namespace hilti;

std::unique_ptr<Logger> Logger::_singleton;

std::map<std::string, logging::DebugStream>& logging::DebugStream::_streams() {
    static std::map<std::string, logging::DebugStream> streams;
    return streams;
}

logging::DebugStream::DebugStream(const std::string& name) : _name(name) {
    auto& _all = _streams();
    if ( auto i = _all.find(name); i != _all.end() )
        _id = i->second._id;
    else {
        _id = _all.size();
        _all.emplace(name, *this);
    }
}

std::vector<std::string> logging::DebugStream::all() {
    std::vector<std::string> keys;

    const auto& _all = _streams();

    keys.reserve(_all.size());
    for ( const auto& s : _all )
        keys.push_back(s.first);

    return keys;
}

logging::Stream::Buffer::Buffer(logging::Level level) : std::stringbuf(std::ios_base::out), _level(level) {
    setp(nullptr, nullptr); // make every character go through overflow()
}

logging::Stream::Buffer::Buffer(logging::DebugStream dbg)
    : std::stringbuf(std::ios_base::out), _level(Level::Debug), _dbg(dbg) {
    setp(nullptr, nullptr); // make every character go through overflow()
}

int logging::Stream::Buffer::sync() {
    if ( _buffer.empty() )
        return 0;

    if ( _dbg )
        logger()._debug(*_dbg, util::rtrim(_buffer));
    else
        logger().log(_level, util::rtrim(_buffer));

    _buffer.clear();
    return 0;
}

int logging::Stream::Buffer::overflow(int ch) {
    if ( ch != traits_type::eof() ) {
        _buffer.push_back(static_cast<std::string::value_type>(ch));

        if ( ch == '\n' )
            sync();
    }

    return ch;
}

std::unique_ptr<Logger> hilti::setLogger(std::unique_ptr<Logger> logger) {
    std::swap(Logger::_singleton, logger);
    return logger;
}

void Logger::debugEnable(const logging::DebugStream& dbg) {
    if ( _debug_streams.find(dbg) == _debug_streams.end() )
        _debug_streams[dbg] = 0;
}

bool Logger::debugEnable(const std::string& dbg) {
    try {
        debugEnable(logging::DebugStream::streamForName(dbg));
        return true;
    } catch ( std::out_of_range& ) {
        return false;
    }
}

bool Logger::debugDisable(const std::string& dbg) {
    try {
        debugDisable(logging::DebugStream::streamForName(dbg));
        return true;
    } catch ( std::out_of_range& ) {
        return false;
    }
}

void Logger::log(logging::Level level, const std::string& msg, const Location& l) {
    report(_output_std, level, 0, "", msg, l);
}

void Logger::info(const std::string& msg, const Location& l) {
    report(_output_std, logging::Level::Info, 0, "", msg, l);
}

void Logger::warning(const std::string& msg, const Location& l) {
    report(_output_std, logging::Level::Warning, 0, "", msg, l);
    ++_warnings;
}

void Logger::deprecated(const std::string& msg, const Location& l) { warning(msg, l); }

void Logger::error(const std::string& msg, const Location& l) { error(msg, {}, l); }

void Logger::error(const std::string& msg, const std::vector<std::string>& context, const Location& l) {
    report(_output_std, logging::Level::Error, 0, "", msg, l);

    for ( const auto& x : context )
        report(_output_std, logging::Level::Error, 0, "", util::fmt("  %s", x), l);

    ++_errors;
}

void Logger::fatalError(const std::string& msg, const Location& l) {
    report(_output_std, logging::Level::FatalError, 0, "", msg, l);
    exit(1);
}

void Logger::internalError(const std::string& msg, const Location& l) {
    report(_output_std, logging::Level::InternalError, 0, "", msg, l);
    util::abort_with_backtrace();
}

void Logger::_debug(const logging::DebugStream& dbg, const std::string& msg, const Location& l) {
    if ( auto i = _debug_streams.find(dbg); i != _debug_streams.end() )
        report(_output_debug, logging::Level::Debug, i->second, dbg.name(), msg, l);
}

void Logger::report(std::ostream& output, logging::Level level, size_t indent, const std::string& addl,
                    const std::string& msg, const Location& l) const {
    std::string level_str = logging::to_string(level);
    std::string indent_str = std::string(static_cast<std::string::size_type>(indent) * 2, ' ');

    if ( level == logging::Level::Debug )
        level_str = util::fmt("debug/%s", addl);

    if ( l )
        output << util::fmt("[%s] %s%s: %s", level_str, indent_str, std::string(l), msg) << std::endl;
    else
        output << util::fmt("[%s] %s%s", level_str, indent_str, msg) << std::endl;
}
