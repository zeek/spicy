// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <arpa/inet.h>

#include <cinttypes>
#include <string>

#include <hilti/rt/extension-points.h>
#include <hilti/rt/fmt.h>
#include <hilti/rt/safe-int.h>

namespace hilti::rt {

/**
 * Represents HILTI's `barrier` type.
 *
 * TODO: This class is not yet fully implemented, more methods will be added.
 */
class Barrier {
public:
    /**
     * Constructs a barrier.
     *
     * @param parties number of parties that must arrive at the barrier before it is released
     */
    explicit Barrier(const hilti::rt::integer::safe<uint64_t>& expected_parties) : _expected(expected_parties) {}

    Barrier() = default;
    Barrier(const Barrier&) = default;
    Barrier(Barrier&&) noexcept = default;
    ~Barrier() = default;

    Barrier& operator=(const Barrier&) = default;
    Barrier& operator=(Barrier&&) noexcept = default;

    /**
     * Returns true if the barrier has been released, meaning all expected
     * parties have arrived.
     */
    bool isReleased() const { return _expected == _arrived; }

    /** Returns true if the barrier has been released. */
    explicit operator bool() const { return isReleased(); }

    /** Returns a printable representation of the barrier's current state. */
    operator std::string() const { return fmt("<barrier %" PRIu64 "/%" PRIu64 ">", _arrived, _expected); }

private:
    integer::safe<uint64_t> _expected = 0;
    integer::safe<uint64_t> _arrived = 0;
};

namespace detail::adl {
inline std::string to_string(const hilti::rt::Barrier& x, adl::tag /*unused*/) { return std::string(x); }
} // namespace detail::adl

inline std::ostream& operator<<(std::ostream& out, const Barrier& x) {
    out << to_string(x);
    return out;
}

} // namespace hilti::rt
