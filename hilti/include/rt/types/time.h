// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <arpa/inet.h>

#include <limits>
#include <string>
#include <variant>

#include <hilti/rt/extension-points.h>
#include <hilti/rt/types/interval.h>

namespace hilti::rt {

/**
 * Represents HILTI's time type. Intervals are stored as nanoseconds
 * resolution as intervals since the UNIX epoch.
 */
class Time {
public:
    struct SecondTag {};
    struct NanosecondTag {};

    /** Constructs null `Time` value. */
    Time() = default;

    /**
     * Constructs an interval from an unsigned integer value.
     *
     * @param nsecs interval in nanoseconds.
     */
    explicit Time(hilti::rt::integer::safe<uint64_t> nsecs, NanosecondTag /*unused*/) : _nsecs(nsecs) {}

    /**
     * Constructs a time from a double value.
     *
     * @param secs seconds since the UNIX epoch.
     */
    explicit Time(double secs, SecondTag /*unused*/)
        : _nsecs([&]() {
              auto x = secs * 1'000'000'000;

              auto limits = std::numeric_limits<uint64_t>();
              if ( x < static_cast<double>(limits.min()) || static_cast<double>(limits.max()) < x )
                  throw RuntimeError(fmt("Seconds %d cannot be represented as Time", secs));

              return integer::safe<uint64_t>(x);
          }()) {}

    Time(const Time&) = default;
    Time(Time&&) noexcept = default;
    ~Time() = default;

    Time& operator=(const Time&) = default;
    Time& operator=(Time&&) noexcept = default;

    /** Returns a UNIX timestmap. */
    double seconds() const { return _nsecs.Ref() / 1e9; }

    /** Returns nanoseconds since epoch. */
    uint64_t nanoseconds() const { return _nsecs; }

    bool operator==(const Time& other) const { return _nsecs == other._nsecs; }
    bool operator!=(const Time& other) const { return _nsecs != other._nsecs; }
    bool operator<(const Time& other) const { return _nsecs < other._nsecs; }
    bool operator<=(const Time& other) const { return _nsecs <= other._nsecs; }
    bool operator>(const Time& other) const { return _nsecs > other._nsecs; }
    bool operator>=(const Time& other) const { return _nsecs >= other._nsecs; }

    Time operator+(const Interval& other) const {
        if ( other.nanoseconds() < 0 && (integer::safe<int64_t>(_nsecs) < (-other.nanoseconds())) )
            throw RuntimeError(fmt("operation yielded negative time %d %d", _nsecs, other.nanoseconds()));

        return Time(_nsecs + other.nanoseconds(), NanosecondTag{});
    }

    Time operator-(const Interval& other) const {
        if ( _nsecs < other.nanoseconds() )
            throw RuntimeError("operation yielded negative time");

        return Time(_nsecs - other.nanoseconds(), NanosecondTag());
    }

    Interval operator-(const Time& other) const {
        return Interval(integer::safe<int64_t>(_nsecs) - integer::safe<int64_t>(other._nsecs),
                        Interval::NanosecondTag());
    }

    /** Returns a human-readable representation of the time. */
    operator std::string() const;

private:
    hilti::rt::integer::safe<uint64_t> _nsecs = 0; ///< Nanoseconds since epoch.
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
