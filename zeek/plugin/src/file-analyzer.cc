// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <zeek-spicy/file-analyzer.h>
#include <zeek-spicy/plugin.h>
#include <zeek-spicy/runtime-support.h>
#include <zeek-spicy/zeek-reporter.h>

using namespace spicy::zeek;
using namespace spicy::zeek::rt;

FileAnalyzer::FileAnalyzer(RecordVal* args, file_analysis::File* file) : ::file_analysis::Analyzer(args, file) {
    cookie::FileAnalyzer cookie;
    cookie.analyzer = this;
    _cookie = cookie;
}

FileAnalyzer::~FileAnalyzer() {}

void FileAnalyzer::Init() {}

void FileAnalyzer::Done() {
    _data.reset();
    _resumable.reset();
}

inline void FileAnalyzer::DebugMsg(const std::string_view& msg, int len, const u_char* data, bool eod) {
#ifdef ZEEK_DEBUG_BUILD
    if ( data ) { // NOLINT(bugprone-branch-clone) pylint believes the two branches are the same
        zeek::rt::debug(_cookie, hilti::rt::fmt("%s: |%s%s| (eod=%s)", msg,
                                                fmt_bytes(reinterpret_cast<const char*>(data), min(40, len)),
                                                len > 40 ? "..." : "", (eod ? "true" : "false")));
    }

    else
        zeek::rt::debug(_cookie, msg);
#endif
}

int FileAnalyzer::FeedChunk(int len, const u_char* data, bool eod) {
    // If a previous parsing process has finished, we ignore all
    // further input.
    if ( _done ) {
        if ( len )
            DebugMsg("further data ignored", len, data, eod);

        return 0;
    }

    if ( ! _parser ) {
        const auto& cookie = std::get<cookie::FileAnalyzer>(_cookie);
        _parser = SpicyPlugin.parserForFileAnalyzer(cookie.analyzer->Tag());

        if ( ! _parser ) {
            DebugMsg("no unit specificed for parsing");
            // Nothing to do at all.
            return 1;
        }
    }

    int result = -1;
    bool done = false;
    bool error = false;

    hilti::rt::context::saveCookie(&_cookie);

    try {
        if ( ! _data ) {
            // First chunk.
            DebugMsg("initial chunk", len, data, eod);
            _data = hilti::rt::ValueReference<hilti::rt::Stream>({reinterpret_cast<const char*>(data), len});

            if ( eod )
                (*_data)->freeze();

            _resumable = _parser->parse1(*_data, {});
        }
        else {
            // Resume parsing.
            DebugMsg("resuming with chunk", len, data, eod);
            assert(_data && _resumable);

            if ( len )
                (*_data)->append(reinterpret_cast<const char*>(data), len);

            if ( eod )
                (*_data)->freeze();

            _resumable->resume();
        }

        if ( *_resumable ) {
            // Done parsing.
            done = true;
            result = 1;
        }
    }

    catch ( const spicy::rt::ParseError& e ) {
        const auto& cookie = std::get<cookie::FileAnalyzer>(_cookie);

        error = true;
        result = 0;

        std::string s = "Spicy parse error: " + e.description();

        if ( e.location().size() )
            s += hilti::rt::fmt("%s (%s)", s, e.location());

        DebugMsg(s.c_str());
        reporter::weird(cookie.analyzer->GetFile(), s);
    }

    catch ( const hilti::rt::Exception& e ) {
        const auto& cookie = std::get<cookie::FileAnalyzer>(_cookie);

        error = true;
        result = 0;

        std::string msg_zeek = e.description();

        std::string msg_dbg = msg_zeek;
        if ( e.location().size() )
            msg_dbg += hilti::rt::fmt("%s (%s)", msg_dbg, e.location());

        DebugMsg(msg_dbg);
        reporter::analyzerError(cookie.analyzer, msg_zeek,
                                e.location()); // this sets Zeek to skip sending any further input
    }

    hilti::rt::context::clearCookie();

    // TODO(robin): For now we just stop on error, later we might attempt to restart
    // parsing.
    if ( eod || done || error ) {
        DebugMsg("done with parsing");
        _done = true;
    }

    return result;
}

bool FileAnalyzer::DeliverStream(const u_char* data, uint64_t len) {
    ::file_analysis::Analyzer::DeliverStream(data, len);

    if ( ! len )
        return true;

    if ( _skip ) {
        DebugMsg("skipping further file data");
        return false;
    }

    int rc = FeedChunk(len, data, false);

    if ( rc >= 0 ) {
        DebugMsg(::hilti::rt::fmt("parsing %s, skipping further file data", (rc > 0 ? "finished" : "failed")));
        _skip = true;
        return false;
    }

    return true;
}

bool FileAnalyzer::Undelivered(uint64_t offset, uint64_t len) {
    ::file_analysis::Analyzer::Undelivered(offset, len);

    DebugMsg("undelivered data, skipping further originator payload");
    _skip = true;
    return false;
}

bool FileAnalyzer::EndOfFile() {
    ::file_analysis::Analyzer::EndOfFile();

    if ( _skip ) {
        DebugMsg("skipping end-of-data delivery");
        return false;
    }

    FeedChunk(0, reinterpret_cast<const u_char*>(""), true);
    return false;
}

::file_analysis::Analyzer* FileAnalyzer::InstantiateAnalyzer(RecordVal* args, file_analysis::File* file) {
    return new FileAnalyzer(args, file);
}
