// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <optional>

// Zeek headers
#include "cookie.h"
#include <analyzer/protocol/tcp/TCP.h>
#include <analyzer/protocol/udp/UDP.h>

#include <hilti/rt/types/stream.h>

#include <spicy/rt/parser.h>

namespace spicy::zeek::rt {

/** Base clase for Spicy protocol analyzers. */
class ProtocolAnalyzer {
public:
    ProtocolAnalyzer(::analyzer::Analyzer* analyzer);
    virtual ~ProtocolAnalyzer();

protected:
    /** Initialize analyzer.  */
    void Init();

    /** Shutdown analyzer. */
    void Done();

    /**
     * Signal that Zeek has flipped the direction of the connection, meaning
     * that originator and responder state need to be swapped.
     */
    void FlipRoles();

    /** State for one endpont of the connection. */
    struct Endpoint {
        const spicy::rt::Parser* parser = nullptr;
        Cookie cookie;
        bool done = false;
        std::optional<hilti::rt::ValueReference<hilti::rt::Stream>> data;
        std::optional<hilti::rt::Resumable> resumable;

        /**
         * Resets the endpoint's input state so that the next data chunk will
         * be parsed just as if it were the first.
         */
        void reset() {
            done = false;
            data.reset();
            resumable.reset();
        };

        /**
         * Swap direction-specific state between two endpoints. We use this
         * when Zeek performance a `FlipRoles()`.
         */
        static void flipRoles(Endpoint* x, Endpoint* y) {
            std::swap(x->parser, y->parser);
            std::swap(x->cookie, y->cookie);
            std::swap(x->done, y->done);
        }
    };

    /**
     * Feeds a chunk of data into one side's parsing.
     *
     * @param is_orig true to use originator-side endpoint state, false for responder
     * @param len number of bytes valid in *data*
     * @param data pointer to data
     * @param eod true if not more data will be coming for this side of the session
     *
     * @return 1 if parsing finished succesfully; -1 0 if parsing failed; and
     * 0 if parsing is not yet complete, and hence yielded waiting for more
     * input. In the former two cases, no further input will be accepted.
     */
    int FeedChunk(bool is_orig, int len, const u_char* data, bool eod);

    /**
     * Resets an endpoint's input state so that the next data chunk will be
     * parsed just as if it were the first.
     *
     * @param is_orig true to reset originator-side endpoint state, false for responder
     */
    void ResetEndpoint(bool is_orig);

    /**
     * Helper returning the current endpoint protocol analyzer state for a
     * requested side.
     *
     * @param is_orig tru to return the originator's state, false for the
     * responder.
     * @return protocol analyzer cookie for the requested side
     */
    cookie::ProtocolAnalyzer& cookie(bool is_orig);

    /** Records a debug message, optionally displaying input data. */
    void DebugMsg(const ProtocolAnalyzer::Endpoint& endp, const std::string_view& msg, int len = 0,
                  const u_char* data = nullptr, bool eod = false);

    /** Records a debug message, optionally displaying input data. */
    void DebugMsg(bool is_orig, const std::string_view& msg, int len = 0, const u_char* data = nullptr,
                  bool eod = false);

private:
    Endpoint originator; /**< Originator-side state. */
    Endpoint responder;  /**< Responder-side state. */
};

/**
 * Spicy analyzer for TCP application-layer protocols. Implements the
 * standard Zeek API.
 */
class TCP_Analyzer : public ProtocolAnalyzer, public ::analyzer::tcp::TCP_ApplicationAnalyzer {
public:
    TCP_Analyzer(::Connection* conn);
    virtual ~TCP_Analyzer();

    // Overriden from Spicy's Analyzer.
    void Init() override;
    void Done() override;
    void DeliverStream(int len, const u_char* data, bool orig) override;
    void Undelivered(uint64_t seq, int len, bool orig) override;
    void EndOfData(bool is_orig) override;
    void FlipRoles() override;

    // Overriden from Zeek's TCP_ApplicationAnalyzer.
    void EndpointEOF(bool is_orig) override;
    void ConnectionClosed(::analyzer::tcp::TCP_Endpoint* endpoint, ::analyzer::tcp::TCP_Endpoint* peer,
                          int gen_event) override;
    void ConnectionFinished(int half_finished) override;
    void ConnectionReset() override;
    void PacketWithRST() override;

    static ::analyzer::Analyzer* InstantiateAnalyzer(Connection* conn);

private:
    bool skip_orig = false;
    bool skip_resp = false;
};

/**
 * Spicy analyzer for UDP application-layer protocols. Implements the
 * standard Zeek API.
 */
class UDP_Analyzer : public ProtocolAnalyzer, public analyzer::Analyzer {
public:
    UDP_Analyzer(::Connection* conn);
    virtual ~UDP_Analyzer();

    // Overriden from Spicy's Analyzer.
    void Init() override;
    void Done() override;
    void DeliverPacket(int len, const u_char* data, bool orig, uint64_t seq, const IP_Hdr* ip, int caplen) override;
    void Undelivered(uint64_t seq, int len, bool orig) override;
    void EndOfData(bool is_orig) override;
    void FlipRoles() override;

    static ::analyzer::Analyzer* InstantiateAnalyzer(Connection* conn);
};

} // namespace spicy::zeek::rt
