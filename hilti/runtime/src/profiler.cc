// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <cinttypes>
#include <unordered_map>

#include <hilti/rt/configuration.h>
#include <hilti/rt/profiler.h>

using namespace hilti::rt;
using namespace hilti::rt::profiler;

// TODO: Move to global runtime state.

struct MeasurementState {
    Measurement m = {};
    uint64_t instances = 0;
};

static std::unordered_map<std::string, MeasurementState> profilers;
static std::optional<Profiler> total_runtime;

inline uint64_t get_time(clockid_t clock_id) {
#if 1
    struct timespec t;
    clock_gettime(clock_id, &t);
    return static_cast<uint64_t>(1000000000) * t.tv_sec + t.tv_nsec;
#else
    return clock_gettime_nsec_np(clock_id);
#endif
}

void Profiler::register_() const { ++profilers[_name].instances; }

Measurement Profiler::snapshot() const {
    if ( ! total_runtime )
        // Profiling not enabled.
        return Measurement();

    Measurement m;
    m.time = get_time(CLOCK_MONOTONIC_RAW);
    return m;
}

void Profiler::record(const Measurement& end) {
    if ( ! *this )
        return; // already recorded

    if ( ! total_runtime )
        // Profiling not enabled.
        return;

    auto& p = profilers[_name];

    // With recursive calls, we only count the top-level.
    assert(p.instances > 0);
    if ( p.instances-- == 1 ) {
        ++p.m.count;
        p.m += (end - _start);
        /*
         * std::cerr << "XXX " << _name << " start=" << _start.time << " end=" << end.time << " diff=" << x.time
         *           << " total_diff=" << p.m.time << std::endl;
         */
    }

    _name = "";
}

void profiler::init() {
    if ( ! configuration::get().enable_profiling )
        return;

    total_runtime = start("init"); // just seed to get a start time in the next line
    total_runtime = start("hlt/total");
}

void profiler::done() {
    if ( ! total_runtime )
        return;

    stop(*total_runtime);
    dump();
}

void profiler::dump() {
    static const auto fmt_header = "#%-49s %10s %10s %10s %10s\n";
    static const auto fmt_data = "%-50s %10" PRIu64 " %10" PRIu64 " %10.2f %10.2f \n";

    std::cerr << "#\n# Profiling results\n#\n";
    std::cerr << fmt(fmt_header, "name", "count", "time", "avg-%", "total-%");

    std::set<std::string> names;
    for ( const auto& [name, _] : profilers )
        names.insert(name);

    auto total_time = static_cast<double>(profilers.at("hlt/total").m.time);

    for ( const auto& name : names ) {
        const auto& p = profilers.at(name).m;

        if ( p.count == 0 )
            continue;

        auto percent = static_cast<double>(p.time) * 100.0 / total_time;
        std::cerr << fmt(fmt_data, name, p.count, p.time, percent / p.count, percent);
    }
}
