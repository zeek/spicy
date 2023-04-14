// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

#include <hilti/rt/configuration.h>
#include <hilti/rt/global-state.h>
#include <hilti/rt/profiler-state.h>

namespace hilti::rt {

class Profiler;

namespace profiler {

std::optional<Profiler> start(std::string_view name);
void stop(std::optional<Profiler>& p);

namespace detail {

// Internal initialization function, called from library's `init()` when
// profiling has been requested.
extern void init();

// Internal shutdown function, called from library's `done()`. Produces a final
// profiling report.
extern void done();

} // namespace detail
} // namespace profiler

/**
 * Class representing one block of code to profile. The constructor records a
 * first measurement, and the destructor records a second. The delta between
 * the two measurements is then added to a global total kept for respective
 * block of code. Blocks are identified through descriptive names, which will
 * be shows as part of the final report.
 *
 * Profilers can't be instantiated directly; use the `start()` and `stop()` API instead.
 */
class Profiler {
public:
    /**
     * Default constructor instantiating a no-op profiler that's not actively
     * recording any measurement. The only purpose of constructor is allowing
     * to pre-allocate a local profiler variable that a real profiler can later be move into.
     */
    Profiler() = default;

    Profiler(const Profiler& other) = delete;
    Profiler(Profiler&& other) = default;

    /** Destructor concluding any pending measurement. */
    ~Profiler() { record(snapshot()); }

    Profiler& operator=(const Profiler& other) = delete;
    Profiler& operator=(Profiler&& other) = default;

    /** Take final measurement and record the delta between first and final. */
    void record(const profiler::Measurement& end);

    /** Returns true if the profiler is currently taking an active measurement. */
    operator bool() const { return ! _name.empty(); }

    /** Take and return a single measurement. */
    static profiler::Measurement snapshot();

protected:
    /**
     * Constructor starting a new measurement. Don't call directly, use
     * `profiler::start()` instead.
     *
     * @param name descriptive, unique name of the block of code to profile
     */
    Profiler(std::string_view name) : _name(name), _start(snapshot()) { _register(); }

private:
    friend std::optional<Profiler> profiler::start(std::string_view name);
    friend void profiler::detail::done();

    void _register() const;

    std::string _name;            // Name of block to profile; empty is not active.
    profiler::Measurement _start; // Initial measurement at construction time.
};

namespace profiler {
/**
 * Start profiling of a code block. The returned profiler will be recording
 * until either `profiler::stop()` is called with it, or until the profiler
 * instances goes out of scope, whatever comes first.
 *
 * @param name descriptive, unique name of the block of code to profile.
 * @return profiler instance representing the active measurement
 */
inline std::optional<Profiler> start(std::string_view name) {
    if ( ::hilti::rt::detail::unsafeGlobalState()->profiling_enabled )
        return Profiler(name);
    else
        return {};
}

/**
 * Stops profiling a block of code, recording the delta between now and when it
 * was started.
 *
 * @param p profiler instance to stop
 */
inline void stop(std::optional<Profiler>& p) {
    if ( p )
        p->record(Profiler::snapshot());
}

/**
 * Retrieves the measurement state for a code block by name, if known.
 * This is primarily for testing purposes.
 *
 * @param name of the block of code to return data for
 * @return measurement state, or unset if no data is available
 */
std::optional<Measurement> get(const std::string& name);

/** Produce end-of-process summary profiling report. */
extern void report();

} // namespace profiler
} // namespace hilti::rt
