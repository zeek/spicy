// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <sys/time.h>

#include <ctime>

#include <hilti/rt/types/time.h>
#include <hilti/rt/util.h>

using namespace hilti::rt;

Time time::current_time() {
    struct timeval tv {};
    if ( gettimeofday(&tv, nullptr) < 0 )
        throw RuntimeError("gettimeofday failed in current_time()");

    double t = double(tv.tv_sec) + double(tv.tv_usec) / 1e6;
    return Time(t, Time::SecondTag());
}

Time::operator std::string() const {
    if ( _nsecs == 0 )
        return "<not set>";

    // NOLINTNEXTLINE(bugprone-narrowing-conversions,cppcoreguidelines-narrowing-conversions)
    double frac = (_nsecs.Ref() % 1000000000) / 1e9;
    time_t secs = _nsecs.Ref() / 1000000000;

    char buffer[60];
    struct tm tm {};
    strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%S", gmtime_r(&secs, &tm));
    auto sfrac = fmt("%.9fZ", frac);
    return fmt("%s.%s", buffer, sfrac.substr(2));
}
