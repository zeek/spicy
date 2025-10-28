// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <sys/socket.h>

#include <hilti/rt/exception.h>
#include <hilti/rt/types/address.h>
#include <hilti/rt/types/integer.h>
#include <hilti/rt/util.h>

using namespace hilti::rt;

void Address::_parse(const std::string& addr) {
    // We need to guess whether it's a struct in_addr or IPv6 address. If
    // there's a colon in there, it's the latter.
    if ( addr.find(':') == std::string::npos ) {
        struct in_addr v4{};
        if ( inet_pton(AF_INET, addr.c_str(), &v4) > 0 )
            _init(v4);
        else
            throw InvalidArgument(fmt("cannot parse IPv4 address '%s'", addr));
    }

    else {
        struct in6_addr v6{};
        if ( inet_pton(AF_INET6, addr.c_str(), &v6) > 0 )
            _init(v6);
        else
            throw InvalidArgument(fmt("cannot parse IPv6 address '%s'", addr));
    }

    // Allow IPv6 addresses to decay to IPv4 addresses to allow specifying
    // IPv4 addresses in a format like `::ffff:192.0.2.128`.
    if ( _family == AddressFamily::IPv6 )
        _family = (_a1 == 0 && (_a2 & 0xffffffff00000000) == 0) ? AddressFamily::IPv4 : AddressFamily::IPv6;
}

void Address::_init(struct in_addr addr) {
    _a1 = 0;
    _a2 = integer::ntoh32(addr.s_addr);
    _family = AddressFamily::IPv4;
}

void Address::_init(struct in6_addr addr) {
    memcpy(&_a1, &addr, 8);
    _a1 = integer::ntoh64(_a1);

    memcpy(&_a2, (reinterpret_cast<char*>(&addr)) + 8, 8);
    _a2 = integer::ntoh64(_a2);

    _family = AddressFamily::IPv6;
}

AddressFamily Address::family() const { return _family; }

Address Address::mask(unsigned int width) const {
    if ( width == 0 )
        return Address{0, 0, _family};

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

    return Address{a1, a2, _family};
}

std::variant<struct in_addr, struct in6_addr> Address::asInAddr() const {
    switch ( _family.value() ) {
        case AddressFamily::IPv4: return in_addr{integer::hton32(_a2)};

        case AddressFamily::IPv6: {
            struct in6_addr v6{};
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

bool Address::operator==(const Address& other) const {
    // NOTE: `_family` is not checked here as IPv4 and IPv6 addresses can be equivalent.
    return _a1 == other._a1 && _a2 == other._a2;
}

Address::operator std::string() const {
    auto in_addr = asInAddr();
    char buffer[INET6_ADDRSTRLEN];

    if ( _family == AddressFamily::Undef )
        return "<bad address>";

    if ( auto* v4 = std::get_if<struct in_addr>(&in_addr) ) {
        if ( inet_ntop(AF_INET, v4, buffer, INET_ADDRSTRLEN) )
            return buffer;

        return "<bad IPv4 address>";
    }
    else {
        auto* v6 = std::get_if<struct in6_addr>(&in_addr);
        assert(v6); // no other possibility

        if ( inet_ntop(AF_INET6, v6, buffer, INET6_ADDRSTRLEN) )
            return buffer;

        return "<bad IPv6 address>";
    }
}

Bytes Address::pack(ByteOrder fmt) const {
    switch ( _family.value() ) {
        case AddressFamily::IPv4: return integer::pack<uint32_t>(_a2, fmt);

        case AddressFamily::IPv6: {
            auto x = integer::pack<uint64_t>(_a1, fmt);
            auto y = integer::pack<uint64_t>(_a2, fmt);

            const bool nbo =
                (fmt == ByteOrder::Little || (fmt == ByteOrder::Host && systemByteOrder() == ByteOrder::Little));

            if ( ! nbo )
                return x + y;
            else
                return y + x;
        }

        case AddressFamily::Undef:; // Intentional fall-through.
    }

    throw RuntimeError("attempt to pack address of undefined family");
}

template<typename T>
static Result<Tuple<Address, T>> _unpack(const T& data, AddressFamily family, ByteOrder fmt) {
    switch ( family.value() ) {
        case AddressFamily::IPv4: {
            if ( data.size() < 4 )
                return result::Error("insufficient data to unpack IPv4 address");

            if ( auto x = integer::unpack<uint32_t>(data, fmt) )
                return {tuple::make(Address(tuple::get<0>(*x)), tuple::get<1>(*x))};
            else
                return x.error();
        }

        case AddressFamily::IPv6: {
            if ( data.size() < 16 )
                return result::Error("insufficient data to unpack IPv6 address");

            const bool nbo =
                fmt != ByteOrder::Little && (fmt != ByteOrder::Host || systemByteOrder() != ByteOrder::Little);

            if ( auto x = integer::unpack<uint64_t>(data, fmt) ) {
                if ( auto y = integer::unpack<uint64_t>(tuple::get<1>(*x), fmt) ) {
                    if ( ! nbo )
                        return {tuple::make(Address(tuple::get<0>(*y), tuple::get<0>(*x)), tuple::get<1>(*y))};
                    else
                        return {tuple::make(Address(tuple::get<0>(*x), tuple::get<0>(*y)), tuple::get<1>(*y))};
                }
                else
                    return y.error();
            }
            else
                return x.error();
        }

        case AddressFamily::Undef: return result::Error("undefined address family for unpacking");
    }

    cannot_be_reached();
}

Result<Tuple<Address, Bytes>> address::unpack(const Bytes& data, AddressFamily family, ByteOrder fmt) {
    return _unpack(data, family, fmt);
}

Result<Tuple<Address, stream::View>> address::unpack(const stream::View& data, AddressFamily family, ByteOrder fmt) {
    return _unpack(data, family, fmt);
}

std::string detail::adl::to_string(const AddressFamily& x, tag /*unused*/) {
    switch ( x.value() ) {
        case AddressFamily::IPv4: return "AddressFamily::IPv4";
        case AddressFamily::IPv6: return "AddressFamily::IPv6";
        case AddressFamily::Undef: return "AddressFamily::Undef";
    }

    cannot_be_reached();
}
