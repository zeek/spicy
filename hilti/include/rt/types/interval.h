// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <arpa/inet.h>

#include <variant>

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
     * Constructs an interval from an unsigned integer value.
     *
     * @param nsecs interval in nanoseconds.
     */
    explicit Interval(hilti::rt::integer::safe<int64_t> nsecs, NanosecondTag /*unused*/) : _nsecs(nsecs) {}

    /**
     * Constructs an interval from an unsigned integer value.
     *
     * @param nsecs interval in nanoseconds.
     */
    explicit Interval(hilti::rt::integer::safe<uint64_t> nsecs, NanosecondTag /*unused*/) : _nsecs(nsecs) {}

    /**
     * Constructs an interval from a double value.
     *
     * @param secs interval in seconds.
     */
    explicit Interval(double secs, SecondTag /*unused*/) : _nsecs(static_cast<int64_t>(secs * 1e9)) {}

    Interval(const Interval&) = default;
    Interval(Interval&&) noexcept = default;
    ~Interval() = default;

    Interval& operator=(const Interval&) = default;
    Interval& operator=(Interval&&) noexcept = default;

    /** Returns interval as seconds. */
    double seconds() const { return _nsecs.Ref() / 1e9; }

    /** Returns interval as nanoseconds. */
    int64_t nanoseconds() const { return _nsecs.Ref(); }

    bool operator==(const Interval& other) const { return _nsecs == other._nsecs; }
    bool operator!=(const Interval& other) const { return _nsecs != other._nsecs; }
    bool operator<(const Interval& other) const { return _nsecs < other._nsecs; }
    bool operator<=(const Interval& other) const { return _nsecs <= other._nsecs; }
    bool operator>(const Interval& other) const { return _nsecs > other._nsecs; }
    bool operator>=(const Interval& other) const { return _nsecs >= other._nsecs; }

    Interval operator+(const Interval& other) const { return Interval(_nsecs + other._nsecs, NanosecondTag()); }
    Interval operator-(const Interval& other) const { return Interval(_nsecs - other._nsecs, NanosecondTag()); }

    Interval operator*(hilti::rt::integer::safe<std::int64_t> i) const { return Interval(_nsecs * i, NanosecondTag()); }

    Interval operator*(hilti::rt::integer::safe<std::uint64_t> i) const {
        return Interval(_nsecs * i.Ref(), NanosecondTag());
    }

    Interval operator*(double i) const { return Interval(integer::safe<int64_t>(_nsecs.Ref() * i), NanosecondTag()); }

    /** Returns true if the interval is non-zero. */
    explicit operator bool() const { return _nsecs.Ref() != 0; }

    /** Returns a humand-readable representation of the interval. */
    operator std::string() const {
        int64_t secs = _nsecs / 1'000'000'000;
        // NOLINTNEXTLINE(bugprone-narrowing-conversions,cppcoreguidelines-narrowing-conversions)
        double frac = (_nsecs.Ref() % 1'000'000'000) / 1e9;
        return fmt("%.6fs", static_cast<double>(secs) + frac);
    }

private:
    integer::safe<int64_t> _nsecs = 0;
};

namespace detail::adl {
inline std::string to_string(const Interval& x, adl::tag /*unused*/) { return x; }

} // namespace detail::adl

inline std::ostream& operator<<(std::ostream& out, const Interval& x) {
    out << to_string(x);
    return out;
}

} // namespace hilti::rt
