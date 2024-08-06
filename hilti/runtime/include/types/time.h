// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <arpa/inet.h>

#include <limits>
#include <string>

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
    explicit Time(const hilti::rt::integer::safe<uint64_t>& nsecs, NanosecondTag /*unused*/);

    /**
     * Constructs a time from a double value.
     *
     * @param secs seconds since the UNIX epoch.
     * @throws OutOfRange if *secs* cannot be represented with the internal resolution
     */
    explicit Time(double secs, SecondTag /*unused*/);

    Time(const Time&) = default;
    Time(Time&&) noexcept = default;
    ~Time() = default;

    Time& operator=(const Time&) = default;
    Time& operator=(Time&&) noexcept = default;

    /** Returns a UNIX timestamp. */
    double seconds() const;

    /** Returns nanoseconds since epoch. */
    uint64_t nanoseconds() const;

    bool operator==(const Time& other) const;
    bool operator!=(const Time& other) const;
    bool operator<(const Time& other) const;
    bool operator<=(const Time& other) const;
    bool operator>(const Time& other) const;
    bool operator>=(const Time& other) const;

    Time operator+(const Interval& other) const;

    Time operator-(const Interval& other) const;

    Interval operator-(const Time& other) const;

    /** Returns a human-readable representation of the time. */
    operator std::string() const;

private:
    hilti::rt::integer::safe<uint64_t> _nsecs = 0; ///< Nanoseconds since epoch.
};

namespace time {
extern Time current_time();
extern Time mktime(uint64_t y, uint64_t m, uint64_t d, uint64_t H, uint64_t M, uint64_t S);
} // namespace time

namespace detail::adl {
std::string to_string(const Time& x, adl::tag /*unused*/);
} // namespace detail::adl

std::ostream& operator<<(std::ostream& out, const Time& x);

} // namespace hilti::rt
