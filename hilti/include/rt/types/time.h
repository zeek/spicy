// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <arpa/inet.h>

#include <variant>

#include <hilti/rt/extension-points.h>
#include <hilti/rt/types/interval.h>

namespace hilti::rt {

/**
 * Represents HILTI's time type. Intervals are stored as nanoseconds
 * resolution as intervals since the UNIX epoch. A value of zero represents
 * an unset time.
 */
class Time {
public:
    /**
     * Constructs a time from a nanoseconds value.
     *
     * @param nsecs nanonseconds since the UNIX epoch.
     */
    explicit Time(uint64_t nsecs = 0) : _nsecs(nsecs) {}

    /**
     * Constructs an interval from an unsigned integer value.
     *
     * @param nsecs interval in nanoseconds.
     */
    explicit Time(hilti::rt::integer::safe<uint64_t> nsecs) : _nsecs(nsecs) {}

    /**
     * Constructs a time from a double value.
     *
     * @param secs seconds since the UNIX epoch.
     */
    explicit Time(double secs) : _nsecs(static_cast<uint64_t>(secs * 1e9)) {}

    /** Constructs an unset time. */
    Time(const Time&) = default;
    Time(Time&&) noexcept = default;
    ~Time() = default;

    Time& operator=(const Time&) = default;
    Time& operator=(Time&&) noexcept = default;

    /** Returns a UNIX timestmap. */
    double seconds() const { return _nsecs / 1e9; }

    /** Returns nanosecs since epoch. */
    uint64_t nanoseconds() const { return _nsecs; }

    bool operator==(const Time& other) const { return _nsecs == other._nsecs; }
    bool operator!=(const Time& other) const { return _nsecs != other._nsecs; }
    bool operator<(const Time& other) const { return _nsecs < other._nsecs; }
    bool operator<=(const Time& other) const { return _nsecs <= other._nsecs; }
    bool operator>(const Time& other) const { return _nsecs > other._nsecs; }
    bool operator>=(const Time& other) const { return _nsecs >= other._nsecs; }

    Time operator+(const Interval& other) const {
        if ( other.nanoseconds() < 0 && (static_cast<int64_t>(_nsecs) < (-other.nanoseconds())) )
            throw RuntimeError("operation yielded negative time");

        return Time(static_cast<uint64_t>(_nsecs + other.nanoseconds()));
    }

    Time operator-(const Interval& other) const {
        if ( static_cast<int64_t>(_nsecs) < other.nanoseconds() )
            throw RuntimeError("operation yielded negative time");

        return Time(static_cast<uint64_t>(_nsecs - other.nanoseconds()));
    }

    Interval operator-(const Time& other) const {
        return Interval(static_cast<int64_t>(_nsecs) - static_cast<int64_t>(other.nanoseconds()));
    }

    /** Returns true if the time is non-zero (i.e., not unset) */
    operator bool() const { return _nsecs == 0.0; }

    /** Returns a human-readable representation of the tiem. */
    operator std::string() const;

private:
    uint64_t _nsecs = 0; // Nanoseconds since epoch};
};

namespace time {
extern Time current_time();
} // namespace time

namespace detail::adl {
inline std::string to_string(const Time& x, adl::tag /*unused*/) { return x; }
} // namespace detail::adl

inline std::ostream& operator<<(std::ostream& out, const Time& x) {
    out << to_string(x);
    return out;
}

} // namespace hilti::rt
