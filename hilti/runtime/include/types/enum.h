#pragma once

#include <string>
#include <variant>

#include <hilti/rt/logging.h>
#include <hilti/rt/type-info.h>

namespace hilti::rt {

namespace enum_ {

/**
 * Returns true if an enum value maps to a known label.
 *
 * @param t enum value
 * @param ti type information corresponding to enum's type
 * @tparam T enum type
 */
template<typename T>
bool has_label(const T& t, const TypeInfo* ti) {
    if ( ti->tag != TypeInfo::Enum )
        internalError("unexpected type info in enum_::has_label");

    for ( const auto& l : ti->enum_->labels() ) {
        if ( l.value != -1 && static_cast<int64_t>(t) == l.value )
            return true;
    }

    return false;
}
} // namespace enum_
} // namespace hilti::rt
