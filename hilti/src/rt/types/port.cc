// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <hilti/rt/types/port.h>
#include <hilti/rt/util.h>

using namespace hilti::rt;

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
        _protocol = Protocol::Undef;

    try {
        _port = std::stoi(s);
    } catch ( ... ) {
        throw RuntimeError("cannot parse port specification");
    }
}

Port::operator std::string() const {
    std::string protocol;

    switch ( _protocol ) {
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
    switch ( x ) {
        case Protocol::ICMP: return "Protocol::ICMP";
        case Protocol::TCP: return "Protocol::TCP";
        case Protocol::UDP: return "Protocol::UDP";
        case Protocol::Undef: return "<unknown protocol>";
    }

    cannot_be_reached();
}
