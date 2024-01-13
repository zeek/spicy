// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <string_view>

#include <hilti/rt/extension-points.h>
#include <hilti/rt/safe-int.h>
#include <hilti/rt/util.h>

namespace hilti::rt {

namespace string {

/* When processing UTF8, how to handle invalid data not representing UTF8 codepoints. */
HILTI_RT_ENUM_WITH_DEFAULT(DecodeErrorStrategy, IGNORE,
                           IGNORE,  // skip data
                           REPLACE, // replace with a place-holder
                           STRICT   // throw a runtime error
);

/**
 * Computes the length of a UTF8 string in number of codepoints.
 *
 * @param s input UTF8 string
 * @param errors how to handle invalid UTF8 encodings
 * @return the length of the input string
 * @throws RuntimeError if the input is not a valid UTF8 string
 */
integer::safe<uint64_t> size(const std::string& s, DecodeErrorStrategy errors = DecodeErrorStrategy::REPLACE);

/**
 * Computes a lower-case version of an UTF8 string.
 *
 * @param s input UTF8 string
 * @param errors how to handle invalid UTF8 encodings
 * @return a lower-case version of the input string
 * @throws RuntimeError if the input is not a valid UTF8 string
 */
std::string lower(const std::string& s, DecodeErrorStrategy errors = DecodeErrorStrategy::REPLACE);

/**
 * Computes a upper-case version of an UTF8 string.
 *
 * @param s input UTF8 string
 * @param errors how to handle invalid UTF8 encodings
 * @return a upper-case version of the input string
 * @throws RuntimeError if the input is not a valid UTF8 string
 */
std::string upper(const std::string& s, DecodeErrorStrategy errors = DecodeErrorStrategy::REPLACE);

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
