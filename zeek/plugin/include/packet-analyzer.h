// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <zeek-spicy/autogen/config.h>

#ifdef HAVE_PACKET_ANALYZERS

#include <memory>
#include <optional>
#include <string>
#include <utility>

#include <hilti/rt/types/stream.h>

#include <spicy/rt/driver.h>
#include <spicy/rt/parser.h>

#include <hilti/base/util.h>

#include <zeek-spicy/cookie.h>
#include <zeek-spicy/zeek-compat.h>

namespace spicy::zeek::rt {

/** Parsing state for a packet. */
class PacketState : public spicy::rt::driver::ParsingState {
public:
    /**
     * Constructor.
     *
     * @param cookie cookie to associated with the packet
     */
    PacketState(Cookie cookie) : ParsingState(spicy::rt::driver::ParsingType::Block), _cookie(std::move(cookie)) {}

    /** Returns the cookie associated with the packet. */
    auto& cookie() { return std::get<cookie::PacketAnalyzer>(_cookie); }

    /**
     * Records a debug message pertaining to the specific file.
     *
     * @param msg message to record
     */
    void DebugMsg(const std::string_view& msg) { debug(msg); }

protected:
    // Overridden from driver::ParsingState.
    void debug(const std::string_view& msg) override;

private:
    Cookie _cookie;
};

/** A Spicy file analyzer. */
class PacketAnalyzer : public ::zeek::packet_analysis::Analyzer {
public:
    PacketAnalyzer(std::string name);
    virtual ~PacketAnalyzer();

    /** Records a debug message. */
    void DebugMsg(const std::string_view& msg) { _state.DebugMsg(msg); }

    static ::zeek::packet_analysis::AnalyzerPtr Instantiate(std::string name) {
        name = ::zeek::util::canonify_name(name);
        return std::make_shared<PacketAnalyzer>(name);
    }

protected:
    // Overridden from Zeek's packet analyzer.
    bool AnalyzePacket(size_t len, const uint8_t* data, ::zeek::Packet* packet) override;

private:
    PacketState _state;
};

} // namespace spicy::zeek::rt

#endif
