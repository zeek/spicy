// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <hilti/ast/node.h>
#include <hilti/base/util.h>

/** Macro around `Logger::__debug` that avoids evaluation of the arguments if nothing is going to get logged. */
#define HILTI_DEBUG(dbg, ...)                                                                                          \
    {                                                                                                                  \
        if ( ::hilti::logger().isEnabled(dbg) )                                                                        \
            ::hilti::logger()._debug(dbg, __VA_ARGS__);                                                                \
    }

namespace hilti {
namespace logging {

/**
 * A named debug stream. Debugging output can be send to it and will be
 * written out during runtime by the `Logger` if it has enabled the stream.
 */
class DebugStream {
public:
    /**
     * @param name name of the stream, which must be unique across all stream
     */
    explicit DebugStream(const std::string& name);
    bool operator<(const DebugStream& other) const { return _id < other._id; }
    const auto& name() const { return _name; }

    /** Returns the names of all available debug streams. */
    static std::vector<std::string> all();

    /** Returns the stream for a given name. The stream must exist. */
    static const auto& streamForName(const std::string& s) { return _streams().at(s); }

private:
    uint64_t _id;
    std::string _name;
    static std::map<std::string, DebugStream>& _streams();
};

namespace debug {} // namespace debug

/** Logging level. */
enum class Level { Debug, Info, Warning, Error, FatalError, InternalError };

namespace detail {
constexpr util::enum_::Value<Level> Levels[] = {
    {.value = Level::Debug, .name = "debug"},
    {.value = Level::Info, .name = "info"},
    {.value = Level::Warning, .name = "warning"},
    {.value = Level::Error, .name = "error"},
    {.value = Level::FatalError, .name = "fatal-error"},
    {.value = Level::InternalError, .name = "internal-error"},
};
} // namespace detail

constexpr auto to_string(Level m) { return util::enum_::to_string(m, detail::Levels); }

namespace level {
constexpr auto from_string(std::string_view s) { return util::enum_::from_string<Level>(s, detail::Levels); }
} // namespace level

/** Ostream-variant that forwards output to the central logger. */
class Stream : public std::ostream {
private:
    class Buffer : public std::stringbuf {
    public:
        Buffer(logging::Level level);
        Buffer(logging::DebugStream dbg);

    private:
        int overflow(int ch) final;
        int sync() final;

        Level _level;
        std::optional<logging::DebugStream> _dbg;
        std::string _buffer;
    };

public:
    /** Creates a stream that sends output to a given logging level. */
    Stream(logging::Level level) : std::ostream(&_buf), _buf(level) {}

    /** Creates a stream that sends output to a given debug stream. */
    Stream(logging::DebugStream dbg) : std::ostream(&_buf), _buf(std::move(dbg)) {}

private:
    Buffer _buf;
};

} // namespace logging

class Logger;

/**
 * Returns the global logger. A default logger singleton is created at
 * startup. A custom logger can be set through `setLogger()`.
 */
inline Logger& logger();

/**
 * Sets a new logger as the global singleton. Returns the previous one.
 */
extern std::unique_ptr<Logger> setLogger(std::unique_ptr<Logger> logger);

/** Logging system. */
class Logger {
public:
    Logger(std::ostream& output_std = std::cerr, std::ostream& output_debug = std::cerr)
        : _output_std(output_std), _output_debug(output_debug) {}

    void log(logging::Level level, const std::string& msg, const Location& l = location::None);

    void info(const std::string& msg, const Location& l = location::None);
    void warning(const std::string& msg, const Location& l = location::None);
    void deprecated(const std::string& msg, const Location& l = location::None);
    void error(const std::string& msg, const Location& l = location::None);
    void error(const std::string& msg, const std::vector<std::string>& context, const Location& l = location::None);
    void fatalError(const std::string& msg, const Location& l = location::None) __attribute__((noreturn));
    void internalError(const std::string& msg, const Location& l = location::None) __attribute__((noreturn));

    void info(const std::string& msg, const Node* n) { info(msg, n->location()); }
    void warning(const std::string& msg, const Node* n) { warning(msg, n->location()); }
    void deprecated(const std::string& msg, const Node* n) { deprecated(msg, n->location()); }
    void error(const std::string& msg, const Node* n) { error(msg, n->location()); }
    void fatalError(const std::string& msg, const Node* n) __attribute__((noreturn)) { fatalError(msg, n->location()); }
    void internalError(const std::string& msg, const Node* n) __attribute__((noreturn)) {
        internalError(msg, n->location());
    }

    /** Use HILTI_DEBUG(...) instead. */
    void _debug(const logging::DebugStream& dbg, const std::string& msg, const Location& l = location::None);

    template<typename T>
    void log(std::string msg, const std::shared_ptr<T>& n) {
        log(msg, n->location());
    }

    template<typename T>
    void info(std::string msg, const std::shared_ptr<T>& n) {
        info(msg, n->location());
    }

    template<typename T>
    void warning(std::string msg, const std::shared_ptr<T>& n) {
        warning(msg, n->location());
    }

    template<typename T>
    void error(std::string msg, const std::shared_ptr<T>& n) {
        error(msg, n->location());
    }

    template<typename T>
    void error(std::string msg, std::vector<std::string> context, const std::shared_ptr<T>& n) {
        error(msg, context, n.location());
    }

    template<typename R, typename T>
    void error(Result<R> r, const std::shared_ptr<T>& n) {
        error(r.error().description(), n.location());
    }

    template<typename T>
    __attribute__((noreturn)) void fatalError(std::string msg, const std::shared_ptr<T>& n) {
        fatalError(msg, n->location());
    }

    template<typename T>
    __attribute__((noreturn)) void internalError(std::string msg, const std::shared_ptr<T>& n) {
        internalError(msg, n->location());
    }

    template<typename T>
    void debug(const logging::DebugStream& dbg, std::string msg, const std::shared_ptr<T>& n) {
        debug(dbg, msg, n->location());
    }

    void debugEnable(const logging::DebugStream& dbg);
    bool debugEnable(const std::string& dbg);
    void debugDisable(const logging::DebugStream& dbg) { _debug_streams.erase(dbg); }
    bool debugDisable(const std::string& dbg);

    bool isEnabled(const logging::DebugStream& dbg) { return _debug_streams.find(dbg) != _debug_streams.end(); }

    void debugPushIndent(const logging::DebugStream& dbg) {
        if ( isEnabled(dbg) )
            _debug_streams[dbg] += 1;
    }

    void debugPopIndent(const logging::DebugStream& dbg) {
        if ( isEnabled(dbg) )
            _debug_streams[dbg] -= 1;
    }

    void debugSetIndent(const logging::DebugStream& dbg, size_t indent) {
        if ( isEnabled(dbg) )
            _debug_streams[dbg] = indent;
    }

    int errors() const { return _errors; }
    int warnings() const { return _warnings; }

    void reset() { _errors = _warnings = 0; }

protected:
    void report(std::ostream& output, logging::Level level, size_t indent, const std::string& addl,
                const std::string& msg, const Location& l) const;

private:
    friend Logger& logger();                                                  // NOLINT
    friend std::unique_ptr<Logger> setLogger(std::unique_ptr<Logger> logger); // NOLINT

    std::ostream& _output_std = std::cerr;
    std::ostream& _output_debug = std::cerr;

    int _warnings = 0;
    int _errors = 0;

    std::map<logging::DebugStream, size_t> _debug_streams;

    static std::unique_ptr<Logger> _singleton;
};

inline Logger& logger() {
    if ( ! Logger::_singleton )
        Logger::_singleton = std::make_unique<Logger>();

    return *Logger::_singleton;
}

namespace logging {

/**
 * Helper class that increases debug indent on construction, and decreases it
 * again on destruction.
 */
class DebugPushIndent {
public:
    DebugPushIndent(const logging::DebugStream& dbg) : _dbg(dbg) { logger().debugPushIndent(_dbg); }
    ~DebugPushIndent() { logger().debugPopIndent(_dbg); }

    DebugPushIndent() = delete;
    DebugPushIndent(const DebugPushIndent&) = delete;
    DebugPushIndent(DebugPushIndent&&) noexcept = delete;
    DebugPushIndent& operator=(const DebugPushIndent&) = delete;
    DebugPushIndent& operator=(DebugPushIndent&&) noexcept = delete;

private:
    const logging::DebugStream& _dbg;
};

} // namespace logging

} // namespace hilti
