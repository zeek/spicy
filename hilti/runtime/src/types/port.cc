// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include "hilti/rt/types/port.h"

#include <hilti/rt/util.h>

using namespace hilti::rt;

Port::Port(uint16_t port, Protocol protocol) : _port(port), _protocol(protocol) {}

void Port::_parse(const std::string& port) {
    const char* s = port.c_str();
    const char* t = s;

    while ( *t && isdigit(*t) )
        ++t;

    if ( s == t || ! *t || ! *(t + 1) || *t != '/' )
        throw RuntimeError("cannot parse port specification");

    if ( strcasecmp(t, "/tcp") == 0 )
        _protocol = Protocol::TCP;

    else if ( strcasecmp(t, "/udp") == 0 )
        _protocol = Protocol::UDP;

    else if ( strcasecmp(t, "/icmp") == 0 )
        _protocol = Protocol::ICMP;

    else
        throw RuntimeError("cannot parse port specification");

    int port_ = -1;

    try {
        port_ = std::stoi(s);
    } catch ( const std::out_of_range& ) {
        throw RuntimeError("cannot parse port specification");
    }

    if ( port_ > std::numeric_limits<uint16_t>::max() ) {
        throw RuntimeError("cannot parse port specification");
    }

    _port = port_;
}

Port::operator std::string() const {
    std::string protocol;

    switch ( _protocol.value() ) {
        case Protocol::ICMP: {
            protocol = "icmp";
            break;
        }
        case Protocol::TCP: {
            protocol = "tcp";
            break;
        }
        case Protocol::UDP: {
            protocol = "udp";
            break;
        }
        case Protocol::Undef: {
            protocol = "<unknown>";
            break;
        }
    }

    return fmt("%u/%s", _port, protocol);
}

std::string hilti::rt::detail::adl::to_string(const Protocol& x, adl::tag /*unused*/) {
    switch ( x.value() ) {
        case Protocol::ICMP: return "ICMP";
        case Protocol::TCP: return "TCP";
        case Protocol::UDP: return "UDP";
        default: return "<unknown protocol>";
    }

    cannot_be_reached();
}
hilti::rt::Port::Port(const std::string& port) { _parse(port); }
uint16_t hilti::rt::Port::port() const { return _port; }
Protocol hilti::rt::Port::protocol() const { return _protocol; }
bool hilti::rt::Port::operator==(const Port& other) const {
    return _port == other._port && _protocol == other._protocol;
}
bool hilti::rt::Port::operator!=(const Port& other) const { return ! (*this == other); }
bool hilti::rt::Port::operator<(const Port& other) const {
    return std::tie(_port, _protocol) < std::tie(other._port, other._protocol);
};
std::string hilti::rt::detail::adl::to_string(const Port& x, adl::tag /*unused*/) { return x; };
std::ostream& hilti::rt::operator<<(std::ostream& out, const Protocol& x) {
    out << to_string(x);
    return out;
}
std::ostream& hilti::rt::operator<<(std::ostream& out, const Port& x) {
    out << to_string(x);
    return out;
}
