// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <arpa/inet.h>

#include <limits>
#include <memory>
#include <string>
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
     * Constructs an interval from an signed integer value.
     *
     * @param nsecs interval in nanoseconds.
     */
    explicit Interval(const hilti::rt::integer::safe<int64_t>& nsecs, NanosecondTag /*unused*/) : _nsecs(nsecs) {}

    /**
     * Constructs an interval from a double value.
     *
     * @param secs interval in seconds.
     * @throws OutOfRange if *secs* cannot be represented with the internal resolution
     */
    explicit Interval(double secs, SecondTag /*unused*/)
        : _nsecs([&]() {
              auto x = secs * 1'000'000'000;

              using limits = std::numeric_limits<int64_t>;
              if ( x < static_cast<double>(limits::min()) || static_cast<double>(limits::max()) < x )
                  throw OutOfRange("value cannot be represented as an interval");

              return integer::safe<int64_t>(x);
          }()) {}

    Interval(const Interval&) = default;
    Interval(Interval&&) noexcept = default;
    ~Interval() = default;

    Interval& operator=(const Interval&) = default;
    Interval& operator=(Interval&&) noexcept = default;

    /** Returns interval as seconds. */
    double seconds() const { return static_cast<double>(_nsecs.Ref()) / 1e9; }

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

    Interval operator*(const hilti::rt::integer::safe<std::int64_t>& i) const {
        return Interval(_nsecs * i, NanosecondTag());
    }

    Interval operator*(const hilti::rt::integer::safe<std::uint64_t>& i) const {
        return Interval(_nsecs * i.Ref(), NanosecondTag());
    }

    Interval operator*(double i) const {
        return Interval(integer::safe<int64_t>(static_cast<double>(_nsecs.Ref()) * i), NanosecondTag());
    }

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
