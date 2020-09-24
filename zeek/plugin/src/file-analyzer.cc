// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <zeek-spicy/autogen/config.h>
#include <zeek-spicy/file-analyzer.h>
#include <zeek-spicy/plugin.h>
#include <zeek-spicy/runtime-support.h>
#include <zeek-spicy/zeek-reporter.h>

using namespace spicy::zeek;
using namespace spicy::zeek::rt;
using namespace plugin::Zeek_Spicy;

void FileState::_debug(const std::string_view& msg) { spicy::zeek::rt::debug(_cookie, msg); }

static auto create_file_state(FileAnalyzer* analyzer) {
    cookie::FileAnalyzer cookie;
    cookie.analyzer = analyzer;
    return FileState(cookie);
}

FileAnalyzer::FileAnalyzer(::zeek::RecordValPtr args, ::zeek::file_analysis::File* file)
    : ::zeek::file_analysis::Analyzer(args, file), _state(create_file_state(this)) {}

FileAnalyzer::~FileAnalyzer() {}

void FileAnalyzer::Init() {}

void FileAnalyzer::Done() {}

bool FileAnalyzer::DeliverStream(const u_char* data, uint64_t len) {
    ::zeek::file_analysis::Analyzer::DeliverStream(data, len);

    return Process(len, data);
}

bool FileAnalyzer::Undelivered(uint64_t offset, uint64_t len) {
    ::zeek::file_analysis::Analyzer::Undelivered(offset, len);

    DebugMsg("undelivered data, skipping further originator payload");
    _state.skipRemaining();
    return false;
}

bool FileAnalyzer::EndOfFile() {
    ::zeek::file_analysis::Analyzer::EndOfFile();
    Finish();
    return false;
}

bool FileAnalyzer::Process(int len, const u_char* data) {
    if ( ! _state.hasParser() && ! _state.isSkipping() ) {
        auto parser = OurPlugin->parserForFileAnalyzer(_state.cookie().analyzer->Tag());
        ;
        if ( parser )
            _state.setParser(parser);
        else {
            DebugMsg("no unit specified for parsing");
            _state.skipRemaining();
            return false;
        }
    }


    try {
        hilti::rt::context::CookieSetter _(&_state.cookie());
        _state.process(len, reinterpret_cast<const char*>(data));
    } catch ( const spicy::rt::ParseError& e ) {
        reporter::weird(_state.cookie().analyzer->GetFile(), e.what());
    } catch ( const hilti::rt::Exception& e ) {
        DebugMsg(e.what());
        reporter::analyzerError(_state.cookie().analyzer, e.description(),
                                e.location()); // this sets Zeek to skip sending any further input
    }

    return true;
}

void FileAnalyzer::Finish() {
    try {
        hilti::rt::context::CookieSetter _(&_state.cookie());
        _state.finish();
    } catch ( const spicy::rt::ParseError& e ) {
        reporter::weird(_state.cookie().analyzer->GetFile(), e.what());
    } catch ( const hilti::rt::Exception& e ) {
        reporter::analyzerError(_state.cookie().analyzer, e.description(),
                                e.location()); // this sets Zeek to skip sending any further input
    }
}

::zeek::file_analysis::Analyzer* FileAnalyzer::InstantiateAnalyzer(::zeek::RecordValPtr args,
                                                                   ::zeek::file_analysis::File* file) {
    return new FileAnalyzer(args, file);
}
