// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <arpa/inet.h>

#include <string>

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
    Network(const Address& prefix, int length);

    /** Constructs a network from prefix address and length.
     *
     * @param prefix prefix address, which's *length* lower bits will be masked out.
     * @param length prefix length, which must be in the range from 0-32 for IPv4
     *        addresses; and 0-128 for IPv6 addresses.
     *
     * @throws RuntimeError if it cannot parse the prefix into a valid IPv4 or IPv6 address.
     * @throws InvalidArgument for invalid length values.
     */
    Network(const std::string& prefix, int length);
    Network(const Network&) = default;
    Network() = default;
    Network(Network&&) noexcept = default;
    ~Network() = default;

    Network& operator=(const Network&) = default;
    Network& operator=(Network&&) noexcept = default;

    /** Returns the network prefix, with the lower bits masked out. */
    const Address& prefix() const;

    /** Returns the protocol family of the network, which can be IPv4 or IPv6. */
    AddressFamily family() const;

    /**
     * Returns the length of the prefix. If the prefix' protocol family is
     * IPv4, this will be between 0 and 32; if IPv6, between 0 and 128.
     */
    int length() const;

    /** Returns true if the network includes a given address. */
    bool contains(const Address& x) const;

    bool operator==(const Network& other) const;
    bool operator!=(const Network& other) const;
    bool operator<(const Network& other) const;

    /**
     * Returns a human-readable representation of the network, using the same
     * format that the corresponding constructor parses.
     */
    operator std::string() const;

private:
    void _mask();

    Address _prefix;
    int _length = 0;
};

namespace detail::adl {
std::string to_string(const Network& x, adl::tag /*unused*/);
} // namespace detail::adl

std::ostream& operator<<(std::ostream& out, const Network& x);

} // namespace hilti::rt
