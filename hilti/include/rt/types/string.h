// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string_view>

#include <string>

#include <hilti/rt/extension-points.h>
#include <hilti/rt/util.h>

namespace hilti::rt {

namespace string {

/** Returns the length of a UTF8 string. */
size_t size(const std::string& s);

/** Returns a lower-case version of an UTF8 string. */
std::string lower(const std::string& s);

/** Returns an upper-case version of an UTF8 string. */
std::string upper(const std::string& s);

} // namespace string

namespace detail::adl {
inline std::string to_string(const std::string& x, adl::tag /*unused*/) {
    return fmt("\"%s\"", escapeUTF8(x, true, true, true));
}

inline std::string to_string(std::string_view x, adl::tag /*unused*/) {
    return fmt("\"%s\"", escapeUTF8(x, true, true, true));
}

template<typename CharT, size_t N>
inline std::string to_string(const CharT (&x)[N], adl::tag /*unused*/) {
    return fmt("\"%s\"", escapeUTF8(x, true, true, true));
}

} // namespace detail::adl

template<>
inline std::string detail::to_string_for_print<std::string>(const std::string& x) {
    return escapeUTF8(x, false, false, true);
}

template<>
inline std::string detail::to_string_for_print<std::string_view>(const std::string_view& x) {
    return escapeUTF8(x, false, false, true);
}


} // namespace hilti::rt
