// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>

#include <hilti/rt/extension-points.h>
#include <hilti/rt/types/address.h>
#include <hilti/rt/util.h>

namespace hilti::rt {

/** Protocols that can be associated with a `Port`. */
HILTI_RT_ENUM(Protocol, TCP = 1, UDP, ICMP, Undef = -1);

/**
 * Represents HILTI's port type. A port is pair of port number and protocol.
 */
class Port {
public:
    /**
     * Constructs a port value. from port number and protocol.
     */
    Port(uint16_t port, Protocol protocol) : _port(port), _protocol(protocol) {}

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
    explicit Port(const std::string& port) { _parse(port); }

    Port() = default;
    Port(const Port&) = default;
    Port(Port&&) noexcept = default;
    ~Port() = default;

    Port& operator=(const Port&) = default;
    Port& operator=(Port&&) noexcept = default;

    /** Returns the port's number. */
    auto port() const { return _port; }

    /** Returns the port's protocol. */
    auto protocol() const { return _protocol; }

    bool operator==(const Port& other) const { return _port == other._port && _protocol == other._protocol; }
    bool operator!=(const Port& other) const { return ! (*this == other); }
    bool operator<(const Port& other) const {
        return std::tie(_port, _protocol) < std::tie(other._port, other._protocol);
    };

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
inline std::string to_string(const Port& x, adl::tag /*unused*/) { return x; };
} // namespace detail::adl

inline std::ostream& operator<<(std::ostream& out, const Protocol& x) {
    out << to_string(x);
    return out;
}

inline std::ostream& operator<<(std::ostream& out, const Port& x) {
    out << to_string(x);
    return out;
}

} // namespace hilti::rt
