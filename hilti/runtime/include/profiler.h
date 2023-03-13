// Copyright (c) 2022-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace hilti::rt {
namespace profiler {

struct Measurement {
    uint64_t count = 0; // not part of computed deltas
    uint64_t time = 0;

    Measurement& operator+=(const Measurement& m) {
        time += m.time;
        return *this;
    }

    Measurement& operator-=(const Measurement& m) {
        time -= m.time;
        return *this;
    }

    Measurement operator+(const Measurement& m) const { return Measurement(*this) += m; }
    Measurement operator-(const Measurement& m) const { return Measurement(*this) -= m; }
};

extern void init();
extern void done();
extern void dump();
} // namespace profiler

class Profiler {
public:
    Profiler() = default;
    Profiler(std::string_view name) : _name(name), _start(snapshot()) { register_(); }
    Profiler(const Profiler& other) = delete;
    Profiler(Profiler&& other) = default;

    ~Profiler() { record(snapshot()); }

    void record(const profiler::Measurement& end);

    Profiler& operator=(const Profiler& other) = delete;
    Profiler& operator=(Profiler&& other) = default;

    operator bool() const { return ! _name.empty(); }

    void register_() const;
    profiler::Measurement snapshot() const;

private:
    friend Profiler start(std::string_view name);

    std::string _name;
    profiler::Measurement _start;
};

namespace profiler {

inline Profiler start(std::string_view name) { return Profiler(name); }
inline void stop(Profiler& p) { p.record(p.snapshot()); }

} // namespace profiler

} // namespace hilti::rt
