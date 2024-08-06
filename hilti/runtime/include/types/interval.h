// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <arpa/inet.h>

#include <string>

#include <hilti/rt/extension-points.h>
#include <hilti/rt/fmt.h>
#include <hilti/rt/safe-int.h>

namespace hilti::rt {

/**
 * Represents HILTI's interval type. Intervals are stored with nanoseconds
 * resolution. Intervals can be either positive or negative.
 */
class Interval {
public:
    struct SecondTag {};
    struct NanosecondTag {};

    Interval() = default;

    /**
     * Constructs an interval from an signed integer value.
     *
     * @param nsecs interval in nanoseconds.
     */
    explicit Interval(const hilti::rt::integer::safe<int64_t>& nsecs, NanosecondTag /*unused*/);

    /**
     * Constructs an interval from a double value.
     *
     * @param secs interval in seconds.
     * @throws OutOfRange if *secs* cannot be represented with the internal resolution
     */
    explicit Interval(double secs, SecondTag /*unused*/);

    Interval(const Interval&) = default;
    Interval(Interval&&) noexcept = default;
    ~Interval() = default;

    Interval& operator=(const Interval&) = default;
    Interval& operator=(Interval&&) noexcept = default;

    /** Returns interval as seconds. */
    double seconds() const;

    /** Returns interval as nanoseconds. */
    int64_t nanoseconds() const;

    bool operator==(const Interval& other) const;
    bool operator!=(const Interval& other) const;
    bool operator<(const Interval& other) const;
    bool operator<=(const Interval& other) const;
    bool operator>(const Interval& other) const;
    bool operator>=(const Interval& other) const;

    Interval operator+(const Interval& other) const;
    Interval operator-(const Interval& other) const;

    Interval operator*(const hilti::rt::integer::safe<std::int64_t>& i) const;

    Interval operator*(const hilti::rt::integer::safe<std::uint64_t>& i) const;

    Interval operator*(double i) const;

    /** Returns true if the interval is non-zero. */
    explicit operator bool() const;

    /** Returns a humand-readable representation of the interval. */
    operator std::string() const;

private:
    integer::safe<int64_t> _nsecs = 0;
};

namespace detail::adl {
std::string to_string(const Interval& x, adl::tag /*unused*/);

} // namespace detail::adl

std::ostream& operator<<(std::ostream& out, const Interval& x);

} // namespace hilti::rt
