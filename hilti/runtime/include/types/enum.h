#pragma once

#include <limits>
#include <string>
#include <type_traits>
#include <variant>

#include <hilti/rt/exception.h>
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

/**
 * Converts a signed integer value into an enum value. The value does
 * not need to correspond to a valid label. (Internally, this is a
 * straight-forward cast.)
 *
 * @param t numerical value to convert
 * @tparam T enum type, which must have int64_t as its underlying type (like
 * all codegen'd enums do)
 */
template<typename T>
T from_int(int64_t n) {
    static_assert(std::is_enum<T>::value && std::is_same_v<std::underlying_type_t<T>, int64_t>);
    return static_cast<T>(n);
}

/**
 * Converts an unsigned integer value into an enum value. The value
 * does not need to correspond to a valid label, but it cannot be
 * larger than the maximum possible signed int64 value. (Internally,
 * this is mostly a straight-forward cast, we just add the range
 * check.)
 *
 * @param t numerical value to convert
 * @tparam T enum type, which must have int64_t as its underlying type (like
 * all codegen'd enums do)
 * @throws InvalidValue if value exceeds range
 */
template<typename T>
T from_uint(uint64_t n) {
    static_assert(std::is_enum<T>::value && std::is_same_v<std::underlying_type_t<T>, int64_t>);

    if ( n > static_cast<uint64_t>(std::numeric_limits<int64_t>::max()) )
        throw InvalidValue("enum value exceeds range");

    return static_cast<T>(n);
}

} // namespace enum_
} // namespace hilti::rt
