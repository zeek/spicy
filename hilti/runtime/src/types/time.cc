// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#ifdef _WIN32
#include <windows.h>
#endif

#include <sys/time.h>

#include <ctime>

#include <hilti/rt/types/time.h>
#include <hilti/rt/util.h>

using namespace hilti::rt;

Time time::current_time() {
#ifdef _WIN32
    // Use Windows native API directly. libunistd's gettimeofday has bugs
    // (wrong divisor and missing epoch offset).
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER li;
    li.LowPart = ft.dwLowDateTime;
    li.HighPart = ft.dwHighDateTime;
    // FILETIME is in 100ns intervals since 1601-01-01.
    // Subtract offset to Unix epoch (1970-01-01) and convert to seconds.
    constexpr uint64_t epoch_offset = 116444736000000000ULL;
    double t = static_cast<double>(li.QuadPart - epoch_offset) / 1e7;
    return Time(t, Time::SecondTag());
#else
    struct timeval tv{};
    if ( gettimeofday(&tv, nullptr) < 0 )
        throw RuntimeError("gettimeofday failed in current_time()");

    double t = static_cast<double>(tv.tv_sec) + (static_cast<double>(tv.tv_usec) / 1e6);
    return Time(t, Time::SecondTag());
#endif
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
    struct tm tm{};
    ::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%S", gmtime_r(&secs, &tm));
    auto sfrac = fmt("%.9fZ", frac);
    return fmt("%s.%s", buffer, sfrac.substr(2));
}
