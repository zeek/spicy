// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <set>
#include <utility>

#include <hilti/base/type_erase.h>
#include <hilti/base/util.h>

using namespace hilti::util;

#ifdef HILTI_TYPE_ERASURE_PROFILE
namespace hilti::util::type_erasure::detail {
inline bool operator<(const Counters& x, const Counters& y) { return x.max >= y.max; }
} // namespace hilti::util::type_erasure::detail
#endif

void type_erasure::summary(std::ostream& out) {
#ifdef HILTI_TYPE_ERASURE_PROFILE
    const auto& unordered = type_erasure::detail::instance_counters();

    int64_t total_max = 0;
    int64_t total_current = 0;

    for ( const auto& [k, v] : unordered ) {
        total_max += v.max;
        total_current += v.current;
    }

    std::set<std::pair<util::type_erasure::detail::Counters, std::string>> ordered;

    for ( const auto& [k, v] : unordered )
        ordered.insert(std::make_pair(v, k));

    out << "\n=== Top-20 type-erased instances (#max/#current)\n\n";

    int count = 20;
    for ( const auto& [v, k] : ordered ) {
        if ( v.max >= 100 )
            out << fmt("%40s  %10d (%5.2f%%)  %10d (%5.2f%%)\n", util::demangle(k), v.max, (100.0 * v.max / total_max),
                       v.current, (100.0 * v.current / total_current));

        if ( --count == 0 )
            break;
    }

    out << "\n";
#else
    out << "\n (No support for type-erase profiling compiled in.)\n\n";
#endif
}
