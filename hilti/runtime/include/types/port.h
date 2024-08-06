// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <arpa/inet.h>

#include <cstdint>
#include <string>

#include <hilti/rt/extension-points.h>
#include <hilti/rt/types/address.h>
#include <hilti/rt/util.h>

namespace hilti::rt {

/** Protocols that can be associated with a `Port`. */
HILTI_RT_ENUM(Protocol, Undef = 0, TCP, UDP, ICMP);

/**
 * Represents HILTI's port type. A port is pair of port number and protocol.
 */
class Port {
public:
    /**
     * Constructs a port value. from port number and protocol.
     */
    Port(uint16_t port, Protocol protocol);

    /**
     * Constructs a port from a textual representation of the form `<port
     * number>/<protocol` (e.g., `123/tcp`)..
     *
     * @param port string of the form  `<port>/<proto>`.
     *
     * @throws RuntimeError if it cannot parse the port specification
     * (whereby, however, an unsupported protocol doesn't count as an error;
     * it'll be left as `Undef`)
     */
    explicit Port(const std::string& port);

    Port() = default;
    Port(const Port&) = default;
    Port(Port&&) noexcept = default;
    ~Port() = default;

    Port& operator=(const Port&) = default;
    Port& operator=(Port&&) noexcept = default;

    /** Returns the port's number. */
    uint16_t port() const;

    /** Returns the port's protocol. */
    Protocol protocol() const;

    bool operator==(const Port& other) const;
    bool operator!=(const Port& other) const;
    bool operator<(const Port& other) const;

    /**
     * Returns a human-readable representation of the port, using the same
     * format that the corresponding constructor parses.
     */
    operator std::string() const;

private:
    // Throws RuntimeError if it cannot parse the address.
    void _parse(const std::string& port);

    uint16_t _port = 0;
    Protocol _protocol = Protocol::Undef;
};

namespace detail::adl {
extern std::string to_string(const Protocol& x, adl::tag /*unused*/);
std::string to_string(const Port& x, adl::tag /*unused*/);
} // namespace detail::adl

std::ostream& operator<<(std::ostream& out, const Protocol& x);

std::ostream& operator<<(std::ostream& out, const Port& x);

} // namespace hilti::rt
