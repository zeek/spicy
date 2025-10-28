// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <cstdint>

#include <hilti/rt/extension-points.h>
#include <hilti/rt/types/optional.h>

namespace hilti::rt::profiler {

/**
 * A measurement taken by the profiler.  We use this both for absolute
 * snapshots at a given point of time, as well as as for deltas between two
 * snapshots. When computing relative deltas, the `count` field is not
 * modified, so that we use it to track total numbers of measurements taken.
 *
 *  While right now record only basic execution times, we could extend
 *  measurements later with further information, such as memory usage and cache
 *  statistics.
 */
struct Measurement {
    uint64_t count = 0;                   /**< Number of measurements taken. */
    uint64_t time = 0;                    /**< Measured time in system-specific high resolution clock. */
    hilti::rt::Optional<uint64_t> volume; /**< Measured absolute volume in bytes, if applicable */

    Measurement& operator+=(const Measurement& m) {
        time += m.time;

        if ( m.volume ) {
            if ( volume )
                *volume += *m.volume;
            else
                volume = m.volume;
        }

        // Don't modify count.

        return *this;
    }

    Measurement& operator-=(const Measurement& m) {
        time -= m.time;

        if ( volume && m.volume )
            *volume -= *m.volume;

        // Don't modify count.

        return *this;
    }

    Measurement operator+(const Measurement& m) const { return Measurement(*this) += m; }
    Measurement operator-(const Measurement& m) const { return Measurement(*this) -= m; }
};

inline std::string to_string(const Measurement&, detail::adl::tag /*unused*/) { return "<profiler measurement>"; }

namespace detail {

// Structure for storing global state.
struct MeasurementState {
    Measurement m = {};
    uint64_t instances = 0;
};

} // namespace detail

} // namespace hilti::rt::profiler
