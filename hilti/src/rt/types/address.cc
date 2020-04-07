// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <hilti/rt/exception.h>
#include <hilti/rt/types/address.h>
#include <hilti/rt/types/integer.h>
#include <hilti/rt/util.h>

using namespace hilti::rt;

void Address::_parse(const std::string& addr) {
    // We need to guess whether it's a struct in_addr or IPv6 address. If
    // there's a colon in there, it's the latter.
    if ( addr.find(':') == std::string::npos ) {
        struct in_addr v4 {};
        if ( inet_pton(AF_INET, addr.c_str(), &v4) > 0 )
            _init(v4);
        else
            throw RuntimeError(fmt("cannot parse IPv4 address '%s'", addr));
    }

    else {
        struct in6_addr v6 {};
        if ( inet_pton(AF_INET6, addr.c_str(), &v6) > 0 )
            _init(v6);
        else
            throw RuntimeError(fmt("cannot parse IPv6 address '%s'", addr));
    }
}

void Address::_init(struct in_addr addr) {
    _a1 = 0;
    _a2 = integer::ntoh32(addr.s_addr);
}

void Address::_init(struct in6_addr addr) {
    memcpy(&_a1, &addr, 8);
    _a1 = integer::ntoh64(_a1);

    memcpy(&_a2, (reinterpret_cast<char*>(&addr)) + 8, 8);
    _a2 = integer::ntoh64(_a2);
}

AddressFamily Address::family() const {
    return (_a1 == 0 && (_a2 & 0xffffffff00000000) == 0) ? AddressFamily::IPv4 : AddressFamily::IPv6;
}

Address Address::mask(unsigned int width) const {
    if ( width == 0 )
        return Address{0, 0};

    uint64_t a1;
    uint64_t a2;

    if ( width < 64 )
        a1 = _a1 & (0xffffffffffffffffU << (64U - width));
    else
        a1 = _a1;

    if ( width > 64 )
        a2 = _a2 & (0xffffffffffffffffU << (128U - width));
    else
        a2 = 0;

    return Address{a1, a2};
}

std::variant<struct in_addr, struct in6_addr> Address::asInAddr() const {
    switch ( family() ) {
        case AddressFamily::IPv4: return in_addr{integer::hton32(_a2)};

        case AddressFamily::IPv6: {
            struct in6_addr v6 {};
            uint64_t a1 = integer::hton64(_a1);
            memcpy(&v6, &a1, 8);

            uint64_t a2 = integer::hton64(_a2);
            memcpy((reinterpret_cast<char*>(&v6)) + 8, &a2, 8);

            return v6;
        }

        case AddressFamily::Undef: {
            return in_addr{0};
        }
    }

    cannot_be_reached();
}

bool Address::operator==(const Address& other) const { return _a1 == other._a1 && _a2 == other._a2; }

Address::operator std::string() const {
    auto in_addr = asInAddr();
    char buffer[INET6_ADDRSTRLEN];

    if ( auto v4 = std::get_if<struct in_addr>(&in_addr) ) {
        if ( inet_ntop(AF_INET, v4, buffer, INET_ADDRSTRLEN) )
            return buffer;

        return "<bad IPv4 address>";
    }
    else {
        auto v6 = std::get_if<struct in6_addr>(&in_addr);
        assert(v6); // no other possibility

        if ( inet_ntop(AF_INET6, v6, buffer, INET6_ADDRSTRLEN) )
            return buffer;

        return "<bad IPv6 address>";
    }
}

template<typename T>
Result<std::tuple<Address, T>> _unpack(const T& data, AddressFamily family, ByteOrder fmt) {
    switch ( family ) {
        case AddressFamily::IPv4: {
            if ( data.size() < 4 )
                return result::Error("insufficient data to unpack IPv4 address");

            if ( auto x = integer::unpack<uint32_t>(data, fmt) )
                return std::make_tuple(Address(std::get<0>(*x)), std::get<1>(*x));
            else
                return x.error();
        }

        case AddressFamily::IPv6: {
            if ( data.size() < 16 )
                return result::Error("insufficient data to unpack IPv6 address");

            const bool nbo =
                ! (fmt == ByteOrder::Little || (fmt == ByteOrder::Host && systemByteOrder() == ByteOrder::Little));

            if ( auto x = integer::unpack<uint64_t>(data, fmt) ) {
                if ( auto y = integer::unpack<uint64_t>(std::get<1>(*x), fmt) ) {
                    if ( ! nbo )
                        return std::make_tuple(Address(std::get<0>(*y), std::get<0>(*x)), std::get<1>(*y));
                    else
                        return std::make_tuple(Address(std::get<0>(*x), std::get<0>(*y)), std::get<1>(*y));
                }
                else
                    return y.error();
            }
            else
                return x.error();
        }

        case AddressFamily::Undef: throw RuntimeError("undefined address family for unpacking");
        default: cannot_be_reached();
    }
}

Result<std::tuple<Address, Bytes>> address::unpack(const Bytes& data, AddressFamily family, ByteOrder fmt) {
    return _unpack(data, family, fmt);
}

Result<std::tuple<Address, stream::View>> address::unpack(const stream::View& data, AddressFamily family,
                                                          ByteOrder fmt) {
    return _unpack(data, family, fmt);
}

std::string detail::adl::to_string(const AddressFamily& x, tag /*unused*/) {
    switch ( x ) {
        case AddressFamily::IPv4: return "AddressFamily::IPv4";
        case AddressFamily::IPv6: return "AddressFamily::IPv6";
        case AddressFamily::Undef: return "AddressFamily::Undef";
    }

    cannot_be_reached();
}
