// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include "hilti/rt/types/time.h"

#include <sys/time.h>

#include <ctime>

#include <hilti/rt/util.h>

using namespace hilti::rt;

Time time::current_time() {
    struct timeval tv {};
    if ( gettimeofday(&tv, nullptr) < 0 )
        throw RuntimeError("gettimeofday failed in current_time()");

    double t = static_cast<double>(tv.tv_sec) + static_cast<double>(tv.tv_usec) / 1e6;
    return Time(t, Time::SecondTag());
}

Time time::mktime(uint64_t y, uint64_t m, uint64_t d, uint64_t H, uint64_t M, uint64_t S) {
    if ( y < 1970 || (m < 1 || m > 12) || (d < 1 || d > 31) || H > 23 || M > 59 || S > 59 )
        throw InvalidValue("value out of range");

    struct tm t;
    t.tm_sec = static_cast<int>(S);
    t.tm_min = static_cast<int>(M);
    t.tm_hour = static_cast<int>(H);
    t.tm_mday = static_cast<int>(d);
    t.tm_mon = static_cast<int>(m) - 1;
    t.tm_year = static_cast<int>(y) - 1900;
    t.tm_isdst = -1;

    time_t teatime = mktime(&t);

    if ( teatime < 0 )
        throw InvalidValue("cannot create time value");

    return Time(static_cast<double>(teatime), Time::SecondTag());
}

Time::operator std::string() const {
    if ( _nsecs == 0 )
        return "<not set>";

    // _NOLINTNEXTLINE(bugprone-narrowing-conversions,cppcoreguidelines-narrowing-conversions)
    double frac = (_nsecs.Ref() % 1000000000) / 1e9;
    // _NOLINTNEXTLINE(bugprone-narrowing-conversions,cppcoreguidelines-narrowing-conversions)
    time_t secs = _nsecs.Ref() / 1000000000;

    char buffer[60];
    struct tm tm {};
    strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%S", gmtime_r(&secs, &tm));
    auto sfrac = fmt("%.9fZ", frac);
    return fmt("%s.%s", buffer, sfrac.substr(2));
}
std::string hilti::rt::detail::adl::to_string(const Time& x, adl::tag /*unused*/) { return x; }
std::ostream& hilti::rt::operator<<(std::ostream& out, const Time& x) {
    out << to_string(x);
    return out;
}
hilti::rt::Time::Time(const hilti::rt::integer::safe<uint64_t>& nsecs, NanosecondTag /*unused*/) : _nsecs(nsecs) {}
hilti::rt::Time::Time(double secs, SecondTag /*unused*/)
    : _nsecs([&]() {
          auto x = secs * 1'000'000'000;

          using limits = std::numeric_limits<uint64_t>;
          if ( x < static_cast<double>(limits::min()) || static_cast<double>(limits::max()) < x )
              throw OutOfRange("value cannot be represented as a time");

          return integer::safe<uint64_t>(x);
      }()) {}
double hilti::rt::Time::seconds() const { return static_cast<double>(_nsecs.Ref()) / 1e9; }
uint64_t hilti::rt::Time::nanoseconds() const { return _nsecs; }
bool hilti::rt::Time::operator==(const Time& other) const { return _nsecs == other._nsecs; }
bool hilti::rt::Time::operator!=(const Time& other) const { return _nsecs != other._nsecs; }
bool hilti::rt::Time::operator<(const Time& other) const { return _nsecs < other._nsecs; }
bool hilti::rt::Time::operator<=(const Time& other) const { return _nsecs <= other._nsecs; }
bool hilti::rt::Time::operator>(const Time& other) const { return _nsecs > other._nsecs; }
bool hilti::rt::Time::operator>=(const Time& other) const { return _nsecs >= other._nsecs; }
hilti::rt::Time hilti::rt::Time::operator+(const Interval& other) const {
    if ( other.nanoseconds() < 0 && (integer::safe<int64_t>(_nsecs) < (-other.nanoseconds())) )
        throw RuntimeError(fmt("operation yielded negative time %d %d", _nsecs, other.nanoseconds()));

    return Time(_nsecs + other.nanoseconds(), NanosecondTag{});
}
hilti::rt::Time hilti::rt::Time::operator-(const Interval& other) const {
    if ( _nsecs < other.nanoseconds() )
        throw RuntimeError("operation yielded negative time");

    return Time(_nsecs - other.nanoseconds(), NanosecondTag());
}
hilti::rt::Interval hilti::rt::Time::operator-(const Time& other) const {
    return Interval(integer::safe<int64_t>(_nsecs) - integer::safe<int64_t>(other._nsecs), Interval::NanosecondTag());
}
