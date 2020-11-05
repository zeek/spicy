// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <zeek-spicy/autogen/config.h>

#ifdef HAVE_PACKET_ANALYZERS

#include <zeek-spicy/packet-analyzer.h>
#include <zeek-spicy/plugin.h>
#include <zeek-spicy/runtime-support.h>
#include <zeek-spicy/zeek-reporter.h>

using namespace spicy::zeek;
using namespace spicy::zeek::rt;
using namespace plugin::Zeek_Spicy;

void PacketState::_debug(const std::string_view& msg) { spicy::zeek::rt::debug(_cookie, msg); }

static auto create_packet_state(PacketAnalyzer* analyzer) {
    cookie::PacketAnalyzer cookie;
    cookie.analyzer = analyzer;
    return PacketState(cookie);
}

PacketAnalyzer::PacketAnalyzer(std::string name)
    : ::zeek::packet_analysis::Analyzer(std::move(name)), _state(create_packet_state(this)) {}

PacketAnalyzer::~PacketAnalyzer() = default;

bool PacketAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, ::zeek::Packet* packet) {
    if ( auto parser = OurPlugin->parserForPacketAnalyzer(_state.cookie().analyzer->GetAnalyzerTag()) )
        _state.setParser(parser);
    else
        reporter::fatalError("no valid unit specified for parsing");

    try {
        hilti::rt::context::CookieSetter _(&_state.cookie());
        _state.cookie().next_analyzer.reset();
        _state.process(len, reinterpret_cast<const char*>(data));
        auto offset = _state.finish();
        assert(offset);
        _state.reset();
        auto num_processed = offset->Ref();
        const auto& next_analyzer = _state.cookie().next_analyzer;
        DebugMsg(hilti::rt::fmt("processed %" PRIu64 " out of %" PRIu64 " bytes, %s", num_processed, len,
                                (next_analyzer ? hilti::rt::fmt("next analyzer is 0x%" PRIx32, *next_analyzer) :
                                                 std::string("no next analyzer"))));
        if ( next_analyzer )
            return ForwardPacket(len - num_processed, data + num_processed, packet, *next_analyzer);
        else
            return true;
    } catch ( const spicy::rt::ParseError& e ) {
        reporter::weird(hilti::rt::fmt("packet analyzer: %s", e.what()));
        _state.reset();
        return false;
    } catch ( const hilti::rt::Exception& e ) {
        DebugMsg(e.what());
        reporter::analyzerError(_state.cookie().analyzer, e.description(),
                                e.location()); // this sets Zeek to skip sending any further input
        _state.reset();
        return false;
    }
}

#endif
