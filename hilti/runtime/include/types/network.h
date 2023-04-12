// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <arpa/inet.h>

#include <string>
#include <variant>

#include <hilti/rt/exception.h>
#include <hilti/rt/extension-points.h>
#include <hilti/rt/types/address.h>
#include <hilti/rt/util.h>

namespace hilti::rt {

/**
 * Represents HILTI's network type.
 */
class Network {
public:
    /**
     * Constructs a network from prefix address and length.
     *
     * @param prefix prefix address, which's *length* lower bits will be masked out.
     * @param length prefix length, which must be in the range from 0-32 for IPv4
     *        addresses; and 0-128 for IPv6 addresses.
     *
     * @throws InvalidArgument for invalid length values.
     */
    Network(const Address& prefix, int length) : _prefix(prefix), _length(length) {
        switch ( _prefix.family().value() ) {
            case AddressFamily::IPv4:
                if ( _length < 0 || _length > 32 )
                    throw InvalidArgument(fmt("prefix length %s is invalid for IPv4 networks", _length));
                break;
            case AddressFamily::IPv6:
                if ( _length < 0 || _length > 128 )
                    throw InvalidArgument(fmt("prefix length %s is invalid for IPv6 networks", _length));
                break;
            case AddressFamily::Undef:
                throw InvalidArgument(
                    fmt("Network can only be constructed from either IPv4 or IPv6 addresses, not %s", prefix));
        }

        _mask();
    }

    /** Constructs a network from prefix address and length.
     *
     * @param prefix prefix address, which's *length* lower bits will be masked out.
     * @param length prefix length, which must be in the range from 0-32 for IPv4
     *        addresses; and 0-128 for IPv6 addresses.
     *
     * @throws RuntimeError if it cannot parse the prefix into a valid IPv4 or IPv6 address.
     * @throws InvalidArgument for invalid length values.
     */
    Network(const std::string& prefix, int length) : _prefix(prefix), _length(length) { _mask(); }
    Network(const Network&) = default;
    Network() = default;
    Network(Network&&) noexcept = default;
    ~Network() = default;

    Network& operator=(const Network&) = default;
    Network& operator=(Network&&) noexcept = default;

    /** Returns the network prefix, with the lower bits masked out. */
    const auto& prefix() const { return _prefix; }

    /** Returns the protocol family of the network, which can be IPv4 or IPv6. */
    auto family() const { return _prefix.family(); }

    /**
     * Returns the length of the prefix. If the prefix' protocol family is
     * IPv4, this will be between 0 and 32; if IPv6, between 0 and 128.
     */
    auto length() const { return (family() == AddressFamily::IPv4 ? _length - 96 : _length); }

    /** Returns true if the network includes a given address. */
    bool contains(const Address& x) const { return x.mask(_length) == _prefix; }

    bool operator==(const Network& other) const { return _prefix == other._prefix && _length == other._length; }
    bool operator!=(const Network& other) const { return ! (*this == other); }
    bool operator<(const Network& other) const {
        return std::tie(_prefix, _length) < std::tie(other._prefix, other._length);
    };

    /**
     * Returns a human-readable representation of the network, using the same
     * format that the corresponding constructor parses.
     */
    operator std::string() const {
        if ( _prefix.family() == AddressFamily::Undef )
            return "<bad network>";

        return fmt("%s/%u", _prefix, length());
    }

private:
    void _mask() {
        if ( _prefix.family() == AddressFamily::IPv4 )
            _length += 96;

        _prefix = _prefix.mask(_length);
    }

    Address _prefix;
    int _length = 0;
};

namespace detail::adl {
inline std::string to_string(const Network& x, adl::tag /*unused*/) { return x; }
} // namespace detail::adl

inline std::ostream& operator<<(std::ostream& out, const Network& x) {
    out << to_string(x);
    return out;
}

} // namespace hilti::rt
