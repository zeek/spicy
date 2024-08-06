// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include "hilti/rt/types/network.h"

namespace hilti::rt {
Network::Network(const Address& prefix, int length) : _prefix(prefix), _length(length) {
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
Network::Network(const std::string& prefix, int length) : _prefix(prefix), _length(length) { _mask(); }
const Address& Network::prefix() const { return _prefix; }
AddressFamily Network::family() const { return _prefix.family(); }
int Network::length() const { return (family() == AddressFamily::IPv4 ? _length - 96 : _length); }
bool Network::contains(const Address& x) const { return x.mask(_length) == _prefix; }
bool Network::operator==(const Network& other) const { return _prefix == other._prefix && _length == other._length; }
bool Network::operator!=(const Network& other) const { return ! (*this == other); }
bool Network::operator<(const Network& other) const {
    return std::tie(_prefix, _length) < std::tie(other._prefix, other._length);
};
Network::operator std::string() const {
    if ( _prefix.family() == AddressFamily::Undef )
        return "<bad network>";

    return fmt("%s/%u", _prefix, length());
}
void Network::_mask() {
    if ( _prefix.family() == AddressFamily::IPv4 )
        _length += 96;

    _prefix = _prefix.mask(_length);
}
std::string detail::adl::to_string(const Network& x, adl::tag /*unused*/) { return x; }
std::ostream& operator<<(std::ostream& out, const Network& x) {
    out << to_string(x);
    return out;
}
} // namespace hilti::rt
