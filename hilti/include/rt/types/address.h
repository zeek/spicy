// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <arpa/inet.h>

#include <string>
#include <tuple>

#include <hilti/rt/extension-points.h>
#include <hilti/rt/result.h>
#include <hilti/rt/types/bytes.h>
#include <hilti/rt/types/stream.h>

namespace hilti::rt {

enum class AddressFamily { Undef, IPv4, IPv6 };

/**
 * Represents HILTI address type. This treats IPv4 and IPv6 addresses
 * transparently by internally embedding the former into the latter's space.
 */
class Address {
public:
    /**
     * Constructs an address from a IPv4 or IPv6 string representation.
     *
     * @param addr string representation, as in `1.2.3.4` or `2001:db8:85a3:8d3:1319:8a2e:370:7348`.
     *
     * @throws RuntimeError if it cannot parse the address into a valid IPv4 or IPv6 address.
     */
    explicit Address(const std::string& addr) { _parse(addr); }

    /** Constructs an address from a C `in_addr` struct. */
    explicit Address(struct in_addr addr4) { _init(addr4); }

    /**
     * Constructs an address from a C `in6_addr` struct.
     */
    explicit Address(struct in6_addr addr6) { _init(addr6); }

    /**
     * Constructs an address from binary representation of an IPv4 address.
     *
     * @param addr4 IPv4 address in host byte order
     */
    explicit Address(uint32_t addr4) : Address(0, addr4, AddressFamily::IPv4) {} // addr4 in host byte order

    /**
     * Constructs an address from binary representation of an IPv6 address.
     *
     * @param addr6a upper bits of IPv6 address in host byte order
     * @param addr6a lower bits of IPv6 address in host byte order
     */
    explicit Address(uint64_t addr6a, uint64_t addr6b, AddressFamily family = AddressFamily::IPv6)
        : _a1(addr6a), _a2(addr6b), _family(family) {}

    Address() noexcept = default;
    Address(const Address&) = default;
    Address(Address&&) noexcept = default;
    ~Address() = default;

    Address& operator=(const Address&) = default;
    Address& operator=(Address&&) noexcept = default;

    /**
     * Returns the address family of the address, which can be either IPv4 or
     * IPv6.
     */
    AddressFamily family() const;

    /**
     * Returns a network prefix by masking out lower bits of the address.
     *
     * @param width number of upper bits to keep.
     */
    Address mask(unsigned int width) const;

    /**
     * Returns the address as `in{,6}_addr` depending on whether it's a v4 or
     * v6 value. For an unset address, returns an IPv4 `0.0.0.0`.
     */
    std::variant<struct in_addr, struct in6_addr> asInAddr() const;

    bool operator==(const Address& other) const;
    bool operator!=(const Address& other) const { return ! (*this == other); }

    /**
     * Returns a string representation of the address. For addresses in the
     * IPv4 space, this will returns the standard IPv4 notation, whereas IPv6
     * addresses will be formatted as such. The returned format corresponds
     * to what the corresponding constructor parses.
     */
    operator std::string() const;

private:
    void _init(struct in_addr addr);
    void _init(struct in6_addr addr);

    // Throws RuntimeError if it cannot parse the address.
    void _parse(const std::string& addr);

    uint64_t _a1 = 0; // The 8 more significant bytes.
    uint64_t _a2 = 0; // The 8 less significant bytes.

    AddressFamily _family = AddressFamily::Undef;
};

namespace address {
/** Unpacks an address from binary representation, following the protocol for `unpack` operator. */
extern Result<std::tuple<Address, Bytes>> unpack(const Bytes& data, AddressFamily family, ByteOrder fmt);

/** Unpacks an address from binary representation, following the protocol for `unpack` operator. */
extern Result<std::tuple<Address, stream::View>> unpack(const stream::View& data, AddressFamily family, ByteOrder fmt);

} // namespace address

namespace detail::adl {
extern std::string to_string(const AddressFamily& x, adl::tag /*unused*/);
inline std::string to_string(const Address& x, adl::tag /*unused*/) { return x; }
} // namespace detail::adl

inline std::ostream& operator<<(std::ostream& out, const Address& x) {
    out << to_string(x);
    return out;
}

inline std::ostream& operator<<(std::ostream& out, const AddressFamily& family) { return out << to_string(family); }

} // namespace hilti::rt
