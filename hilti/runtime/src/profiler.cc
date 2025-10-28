// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <cinttypes>
#include <unordered_map>

#include <hilti/rt/configuration.h>
#include <hilti/rt/logging.h>
#include <hilti/rt/profiler.h>
#include <hilti/rt/util.h>

using namespace hilti::rt;
using namespace hilti::rt::profiler;

// Helper to get a platform-specific, monotonic high-resolution clock.
inline static uint64_t _getClock() {
#if defined(__APPLE__)
    return clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW);
#else
    struct timespec t;
#if defined(__linux__)
    clock_gettime(CLOCK_MONOTONIC_RAW, &t);
#elif defined(__FreeBSD__)
    clock_gettime(CLOCK_MONOTONIC_PRECISE, &t);
#else
    clock_gettime(CLOCK_MONOTONIC, &t); // POSIX
#endif
    return (static_cast<uint64_t>(1000000000) * t.tv_sec) + t.tv_nsec;
#endif
}

void Profiler::_register() const { ++detail::globalState()->profilers[_name].instances; }

profiler::Measurement Profiler::snapshot(hilti::rt::Optional<uint64_t> volume) {
    if ( ! detail::globalState()->profiling_enabled )
        return Measurement();

    Measurement m;
    m.time = _getClock();
    m.volume = volume;
    return m;
}

void Profiler::record(const Measurement& end) {
    if ( ! detail::globalState()->profiling_enabled )
        return;

    if ( ! *this )
        return; // already recorded

    auto& p = detail::globalState()->profilers[_name];
    assert(p.instances > 0);

    ++p.m.count;

    // With recursive calls, we only time the top-level.
    if ( p.instances-- == 1 )
        p.m += (end - _start);

    _name.clear();
}

void profiler::detail::init() {
    if ( ! configuration::get().enable_profiling )
        return;

    rt::detail::globalState()->profiling_enabled = true;

    auto& p = rt::detail::globalState()->profilers["hilti/total"];
    p.m = Profiler::snapshot();
}

void profiler::detail::done() {
    if ( ! rt::detail::globalState()->profiling_enabled )
        return;

    auto& p = rt::detail::globalState()->profilers["hilti/total"];
    p.m = (Profiler::snapshot() - p.m);
    ++p.m.count;

    report();
}

hilti::rt::Optional<Measurement> profiler::get(const std::string& name) {
    const auto& profilers = rt::detail::globalState()->profilers;
    if ( auto i = profilers.find(name); i != profilers.end() )
        return i->second.m;
    else
        return {};
}

void profiler::report() {
    static const auto* const fmt_header = "#%-49s %10s %10s %10s %10s %15s\n";
    static const auto* const fmt_data = "%-50s %10" PRIu64 " %10" PRIu64 " %10.2f %10.2f %15s\n";

    const auto& profilers = rt::detail::globalState()->profilers;

    std::cerr << "#\n# Profiling results\n#\n";
    std::cerr << fmt(fmt_header, "name", "count", "time", "avg-%", "total-%", "volume");

    std::set<std::string> names;
    for ( const auto& [name, _] : profilers )
        names.insert(name);

    auto total_time = static_cast<double>(profilers.at("hilti/total").m.time);

    for ( const auto& name : names ) {
        const auto& p = profilers.at(name).m;

        if ( p.count == 0 )
            continue;

        auto percent = static_cast<double>(p.time) * 100.0 / total_time;

        std::string volume = "-";
        if ( p.volume )
            volume = fmt("%" PRIu64, *p.volume);

        std::cerr << fmt(fmt_data, name, p.count, p.time, percent / static_cast<double>(p.count), percent, volume);
    }
}
