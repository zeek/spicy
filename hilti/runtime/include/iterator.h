// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <iterator>

#include <hilti/rt/exception.h>

namespace hilti::rt {

namespace iterator::detail {

/** Proxy class returned by `range`.  */
template<typename T>
class Range {
public:
    Range(const T& t) : _t(t) {}

    Range(const Range&) = delete;
    Range(Range&&) = delete;
    Range& operator=(const Range&) = delete;
    Range& operator=(Range&&) = delete;

    auto begin() const { return std::begin(_t); }
    auto end() const { return std::end(_t); }

private:
    const T& _t;
};

} // namespace iterator::detail
/**
 * Wrapper that returns an object suitable to operate
 * range-based for loop on to iterator over a sequence.
 */
template<typename T>
auto range(const T& t) {
    return iterator::detail::Range(t);
}
} // namespace hilti::rt
