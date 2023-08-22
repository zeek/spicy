// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <arpa/inet.h>

#include <cinttypes>
#include <string>

#include <hilti/rt/extension-points.h>
#include <hilti/rt/fiber.h>
#include <hilti/rt/fmt.h>
#include <hilti/rt/safe-int.h>

namespace hilti::rt {

/** Represents HILTI's `barrier` type. */
class Barrier {
public:
    /**
     * Constructs a barrier.
     *
     * @param parties number of parties that must arrive at the barrier before it is released
     */
    explicit Barrier(const hilti::rt::integer::safe<uint64_t>& expected_parties) : _expected(expected_parties) {}

    /**
     * Default constructor creating a barrier expecting no parties, meaning
     * that it will start out as released already.
     */
    Barrier() = default;

    Barrier(const Barrier&) = default;
    Barrier(Barrier&&) noexcept = default;
    ~Barrier() = default;

    /**
     * Blocks the caller until the barrier is released. If the barrier is
     * already released, it will return immediately. If not, it will yield back
     * to the runtime system, and re-check the barrier state when resumed.
     *
     * @throws BarrierAborted if the barrier is aborted either immediately at
     * initial call time or at a later resume
     */
    void wait();

    /**
     * Signals a party's arrival at the barrier, potentially releasing it if
     * the expected number of parties have been seen now. This has no effect if
     * the barrier is already released or aborted.
     */
    void arrive();

    /**
     * Convenience method combining a `arrive()` with an immediately following
     * `wait()`.
     */
    void arrive_and_wait() {
        arrive();
        wait();
    }

    /**
     * Aborts operation of the barrier. That means that all parties waiting for
     * it now or later, will receive a `BarrierAborted` exception. This method
     * has no effect if the barrier has already been released.
     */
    void abort();

    /**
     * Returns true if the expected number of parties has arrived at the
     * barrier.
     */
    bool isReleased() const { return _expected >= 0 && _expected == _arrived; }

    /**
     * Returns true if the barrier received an abort() before it could get
     * released.
     */
    bool isAborted() const { return _expected < 0; }

    /** Returns true if the barrier has been released. */
    explicit operator bool() const { return isReleased(); }

    /** Returns a printable representation of the barrier's current state. */
    operator std::string() const;

    Barrier& operator=(const Barrier&) = default;
    Barrier& operator=(Barrier&&) noexcept = default;

private:
    integer::safe<int64_t> _expected = 0;
    integer::safe<int64_t> _arrived = 0;
};

namespace detail::adl {
inline std::string to_string(const hilti::rt::Barrier& x, adl::tag /*unused*/) { return std::string(x); }
} // namespace detail::adl

inline std::ostream& operator<<(std::ostream& out, const Barrier& x) {
    out << to_string(x);
    return out;
}

} // namespace hilti::rt
