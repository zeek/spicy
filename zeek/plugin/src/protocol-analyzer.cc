// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <zeek-spicy/plugin.h>
#include <zeek-spicy/protocol-analyzer.h>
#include <zeek-spicy/runtime-support.h>
#include <zeek-spicy/zeek-reporter.h>

using namespace spicy::zeek;
using namespace spicy::zeek::rt;
using namespace plugin::Zeek_Spicy;

ProtocolAnalyzer::ProtocolAnalyzer(::analyzer::Analyzer* analyzer) {
    static uint64_t analyzer_counter = 0;

    cookie::ProtocolAnalyzer orig_cookie;
    orig_cookie.analyzer = analyzer;
    orig_cookie.is_orig = true;
    orig_cookie.analyzer_id = ++analyzer_counter;
    originator.cookie = orig_cookie;

    cookie::ProtocolAnalyzer resp_cookie;
    resp_cookie.analyzer = analyzer;
    resp_cookie.is_orig = false;
    resp_cookie.analyzer_id = analyzer_counter;
    responder.cookie = resp_cookie;
}

ProtocolAnalyzer::~ProtocolAnalyzer() {}

void ProtocolAnalyzer::Init() {}

void ProtocolAnalyzer::Done() {
    originator.data.reset();
    originator.resumable.reset();

    responder.data.reset();
    responder.resumable.reset();
}

inline void ProtocolAnalyzer::DebugMsg(const ProtocolAnalyzer::Endpoint& endp, const std::string_view& msg, int len,
                                       const u_char* data, bool eod) {
#ifdef ZEEK_DEBUG_BUILD
    if ( data ) { // NOLINT(bugprone-branch-clone) pylint believes the two branches are the same
        zeek::rt::debug(endp.cookie, hilti::rt::fmt("%s: |%s%s| (eod=%s)", msg,
                                                    fmt_bytes(reinterpret_cast<const char*>(data), min(40, len)),
                                                    len > 40 ? "..." : "", (eod ? "true" : "false")));
    }

    else
        zeek::rt::debug(endp.cookie, msg);
#endif
}

void ProtocolAnalyzer::DebugMsg(bool is_orig, const std::string_view& msg, int len, const u_char* data, bool eod) {
    Endpoint* endp = is_orig ? &originator : &responder;
    return DebugMsg(*endp, msg, len, data, eod);
}

int ProtocolAnalyzer::FeedChunk(bool is_orig, int len, const u_char* data, bool eod) {
    Endpoint* endp = is_orig ? &originator : &responder;

    // If a previous parsing process has fully finished, we ignore all
    // further input.
    if ( endp->done ) {
        if ( len )
            DebugMsg(*endp, "further data ignored", len, data, eod);

        return 0;
    }

    if ( ! endp->parser ) {
        const auto& cookie = std::get<cookie::ProtocolAnalyzer>(endp->cookie);
        endp->parser = OurPlugin->parserForProtocolAnalyzer(cookie.analyzer->GetAnalyzerTag(), is_orig);

        if ( ! endp->parser ) {
            DebugMsg(*endp, "no unit specificed for parsing");
            // Nothing to do at all.
            return 1;
        }
    }

    int result = -1;
    bool done = false;
    bool error = false;

    hilti::rt::context::saveCookie(&endp->cookie);

    try {
        if ( ! endp->data ) {
            // First chunk.
            DebugMsg(*endp, "initial chunk", len, data, eod);
            endp->data = hilti::rt::ValueReference<hilti::rt::Stream>({reinterpret_cast<const char*>(data), len});

            if ( eod )
                (*endp->data)->freeze();

            endp->resumable = endp->parser->parse1(*endp->data, {});
        }

        else {
            // Resume parsing.
            DebugMsg(*endp, "resuming with chunk", len, data, eod);
            assert(endp->data && endp->resumable);

            if ( len )
                (*endp->data)->append(reinterpret_cast<const char*>(data), len);

            if ( eod )
                (*endp->data)->freeze();

            endp->resumable->resume();
        }

        if ( *endp->resumable ) {
            // Done parsing.
            done = true;
            result = 1;
        }
    }

    catch ( const spicy::rt::ParseError& e ) {
        const auto& cookie = std::get<cookie::ProtocolAnalyzer>(endp->cookie);

        error = true;
        result = 0;

        std::string s = "Spicy parse error: " + e.description();

        if ( e.location().size() )
            s += hilti::rt::fmt("%s (%s)", s, e.location());

        DebugMsg(*endp, s.c_str());
        reporter::weird(cookie.analyzer->Conn(), s);
    }

    catch ( const hilti::rt::Exception& e ) {
        const auto& cookie = std::get<cookie::ProtocolAnalyzer>(endp->cookie);

        error = true;
        result = 0;

        std::string msg_zeek = e.description();

        std::string msg_dbg = msg_zeek;
        if ( e.location().size() )
            msg_dbg += hilti::rt::fmt("%s (%s)", msg_dbg, e.location());

        DebugMsg(*endp, msg_dbg);
        reporter::analyzerError(cookie.analyzer, msg_zeek,
                                e.location()); // this sets Zeek to skip sending any further input
    }

    hilti::rt::context::clearCookie();

    // TODO(robin): For now we just stop on error, later we might attempt to restart
    // parsing.
    if ( eod || done || error ) {
        DebugMsg(*endp, "done with parsing");
        endp->done = true; // Marker that we're done parsing.
    }

    return result;
}

void ProtocolAnalyzer::ResetEndpoint(bool is_orig) {
    if ( is_orig )
        originator.reset();
    else
        responder.reset();
}

cookie::ProtocolAnalyzer& ProtocolAnalyzer::cookie(bool is_orig) {
    if ( is_orig )
        return std::get<cookie::ProtocolAnalyzer>(originator.cookie);
    else
        return std::get<cookie::ProtocolAnalyzer>(responder.cookie);
}

void ProtocolAnalyzer::FlipRoles() { Endpoint::flipRoles(&originator, &responder); }

::analyzer::Analyzer* TCP_Analyzer::InstantiateAnalyzer(::Connection* conn) { return new TCP_Analyzer(conn); }

TCP_Analyzer::TCP_Analyzer(Connection* conn) : ProtocolAnalyzer(this), ::analyzer::tcp::TCP_ApplicationAnalyzer(conn) {}

TCP_Analyzer::~TCP_Analyzer() {}

void TCP_Analyzer::Init() {
    ::analyzer::tcp::TCP_ApplicationAnalyzer::Init();
    ProtocolAnalyzer::Init();
}

void TCP_Analyzer::Done() {
    ::analyzer::tcp::TCP_ApplicationAnalyzer::Done();
    ProtocolAnalyzer::Done();

    EndOfData(true);
    EndOfData(false);
}

void TCP_Analyzer::DeliverStream(int len, const u_char* data, bool is_orig) {
    ::analyzer::tcp::TCP_ApplicationAnalyzer::DeliverStream(len, data, is_orig);

    if ( is_orig && skip_orig ) {
        DebugMsg(is_orig, "skipping further originator-side traffic");
        return;
    }

    if ( (! is_orig) && skip_resp ) {
        DebugMsg(is_orig, "skipping further responder-side traffic");
        return;
    }

    if ( TCP() && TCP()->IsPartial() ) {
        DebugMsg(is_orig, "skipping further data on partial TCP connection");
        return;
    }

    int rc = FeedChunk(is_orig, len, data, false);

    if ( rc >= 0 ) {
        if ( is_orig ) {
            DebugMsg(is_orig, ::hilti::rt::fmt("parsing %s, skipping further originator payload",
                                               (rc > 0 ? "finished" : "failed")));
            skip_orig = true;
        }
        else {
            DebugMsg(is_orig, ::hilti::rt::fmt("parsing %s, skipping further responder payload",
                                               (rc > 0 ? "finished" : "failed")));
            skip_resp = true;
        }

        if ( skip_orig && skip_resp ) {
            DebugMsg(is_orig, "both endpoints finished, skipping all further TCP processing");
            SetSkip(true);
        }
    }
}

void TCP_Analyzer::Undelivered(uint64_t seq, int len, bool is_orig) {
    ::analyzer::tcp::TCP_ApplicationAnalyzer::Undelivered(seq, len, is_orig);

    // This mimics the (modified) Zeek HTTP analyzer. Otherwise stop parsing
    // the connection
    if ( is_orig ) {
        DebugMsg(is_orig, "undelivered data, skipping further originator payload");
        skip_orig = true;
    }
    else {
        DebugMsg(is_orig, "undelivered data, skipping further responder payload");
        skip_resp = true;
    }
}

void TCP_Analyzer::EndOfData(bool is_orig) {
    ::analyzer::tcp::TCP_ApplicationAnalyzer::EndOfData(is_orig);

    if ( is_orig && skip_orig ) {
        DebugMsg(is_orig, "skipping end-of-data delivery");
        return;
    }

    if ( (! is_orig) && skip_resp ) {
        DebugMsg(is_orig, "skipping end-of-data delivery");
        return;
    }

    if ( TCP() && TCP()->IsPartial() ) {
        DebugMsg(is_orig, "skipping end-of-data delivery on partial TCP connection");
        return;
    }

    FeedChunk(is_orig, 0, reinterpret_cast<const u_char*>(""), true);
}

void TCP_Analyzer::FlipRoles() {
    ::analyzer::tcp::TCP_ApplicationAnalyzer::FlipRoles();
    ProtocolAnalyzer::FlipRoles();
}

void TCP_Analyzer::EndpointEOF(bool is_orig) {
    ::analyzer::tcp::TCP_ApplicationAnalyzer::EndpointEOF(is_orig);
    FeedChunk(is_orig, 0, reinterpret_cast<const u_char*>(""), true);
}

void TCP_Analyzer::ConnectionClosed(::analyzer::tcp::TCP_Endpoint* endpoint, ::analyzer::tcp::TCP_Endpoint* peer,
                                    int gen_event) {
    ::analyzer::tcp::TCP_ApplicationAnalyzer::ConnectionClosed(endpoint, peer, gen_event);
}

void TCP_Analyzer::ConnectionFinished(int half_finished) {
    ::analyzer::tcp::TCP_ApplicationAnalyzer::ConnectionFinished(half_finished);
}

void TCP_Analyzer::ConnectionReset() { ::analyzer::tcp::TCP_ApplicationAnalyzer::ConnectionReset(); }

void TCP_Analyzer::PacketWithRST() { ::analyzer::tcp::TCP_ApplicationAnalyzer::PacketWithRST(); }

::analyzer::Analyzer* UDP_Analyzer::InstantiateAnalyzer(Connection* conn) { return new UDP_Analyzer(conn); }

UDP_Analyzer::UDP_Analyzer(Connection* conn) : ProtocolAnalyzer(this), ::analyzer::Analyzer(conn) {}

UDP_Analyzer::~UDP_Analyzer() {}

void UDP_Analyzer::Init() {
    ::analyzer::Analyzer::Init();
    ProtocolAnalyzer::Init();
}

void UDP_Analyzer::Done() {
    ::analyzer::Analyzer::Done();
    ProtocolAnalyzer::Done();
}

void UDP_Analyzer::DeliverPacket(int len, const u_char* data, bool is_orig, uint64_t seq, const IP_Hdr* ip,
                                 int caplen) {
    ::analyzer::Analyzer::DeliverPacket(len, data, is_orig, seq, ip, caplen);

    ++cookie(is_orig).num_packets;
    FeedChunk(is_orig, len, data, true);
    ResetEndpoint(is_orig);
}

void UDP_Analyzer::Undelivered(uint64_t seq, int len, bool is_orig) {
    ::analyzer::Analyzer::Undelivered(seq, len, is_orig);
}

void UDP_Analyzer::EndOfData(bool is_orig) { ::analyzer::Analyzer::EndOfData(is_orig); }

void UDP_Analyzer::FlipRoles() {
    ::analyzer::Analyzer::FlipRoles();
    ProtocolAnalyzer::FlipRoles();
}
