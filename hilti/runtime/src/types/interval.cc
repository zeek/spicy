// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include "hilti/rt/types/interval.h"

#include <limits>

namespace hilti::rt {
Interval::Interval(const hilti::rt::integer::safe<int64_t>& nsecs, NanosecondTag /*unused*/) : _nsecs(nsecs) {}
Interval::Interval(double secs, SecondTag /*unused*/)
    : _nsecs([&]() {
          auto x = secs * 1'000'000'000;

          using limits = std::numeric_limits<int64_t>;
          if ( x < static_cast<double>(limits::min()) || static_cast<double>(limits::max()) < x )
              throw OutOfRange("value cannot be represented as an interval");

          return integer::safe<int64_t>(x);
      }()) {}
double Interval::seconds() const { return static_cast<double>(_nsecs.Ref()) / 1e9; }
int64_t Interval::nanoseconds() const { return _nsecs.Ref(); }
bool Interval::operator==(const Interval& other) const { return _nsecs == other._nsecs; }
bool Interval::operator!=(const Interval& other) const { return _nsecs != other._nsecs; }
bool Interval::operator<(const Interval& other) const { return _nsecs < other._nsecs; }
bool Interval::operator<=(const Interval& other) const { return _nsecs <= other._nsecs; }
bool Interval::operator>(const Interval& other) const { return _nsecs > other._nsecs; }
bool Interval::operator>=(const Interval& other) const { return _nsecs >= other._nsecs; }
Interval Interval::operator+(const Interval& other) const { return Interval(_nsecs + other._nsecs, NanosecondTag()); }
Interval Interval::operator-(const Interval& other) const { return Interval(_nsecs - other._nsecs, NanosecondTag()); }
Interval Interval::operator*(const hilti::rt::integer::safe<std::int64_t>& i) const {
    return Interval(_nsecs * i, NanosecondTag());
}
Interval Interval::operator*(const hilti::rt::integer::safe<std::uint64_t>& i) const {
    return Interval(_nsecs * i.Ref(), NanosecondTag());
}
Interval Interval::operator*(double i) const {
    return Interval(integer::safe<int64_t>(static_cast<double>(_nsecs.Ref()) * i), NanosecondTag());
}
Interval::operator bool() const { return _nsecs.Ref() != 0; }
Interval::operator std::string() const {
    int64_t secs = _nsecs / 1'000'000'000;
    // NOLINTNEXTLINE(bugprone-narrowing-conversions,cppcoreguidelines-narrowing-conversions)
    double frac = (_nsecs.Ref() % 1'000'000'000) / 1e9;
    return fmt("%.6fs", static_cast<double>(secs) + frac);
}
std::string detail::adl::to_string(const Interval& x, adl::tag /*unused*/) { return x; }
std::ostream& operator<<(std::ostream& out, const Interval& x) {
    out << to_string(x);
    return out;
}
} // namespace hilti::rt
