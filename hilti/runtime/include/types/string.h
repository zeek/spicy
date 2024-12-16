// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <string_view>
#include <tuple>

#include <hilti/rt/extension-points.h>
#include <hilti/rt/safe-int.h>
#include <hilti/rt/types/vector.h>
#include <hilti/rt/unicode.h>
#include <hilti/rt/util.h>

namespace hilti::rt {

class Bytes;

namespace string {

/**
 * Computes the length of a UTF8 string in number of codepoints.
 *
 * @param s input UTF8 string
 * @param errors how to handle invalid UTF8 encodings
 * @return the length of the input string
 * @throws RuntimeError if the input is not a valid UTF8 string
 */
integer::safe<uint64_t> size(const std::string& s,
                             unicode::DecodeErrorStrategy errors = unicode::DecodeErrorStrategy::REPLACE);

/**
 * Computes a lower-case version of an UTF8 string.
 *
 * @param s input UTF8 string
 * @param errors how to handle invalid UTF8 encodings
 * @return a lower-case version of the input string
 * @throws RuntimeError if the input is not a valid UTF8 string
 */
std::string lower(std::string_view s, unicode::DecodeErrorStrategy errors = unicode::DecodeErrorStrategy::REPLACE);

/**
 * Computes a upper-case version of an UTF8 string.
 *
 * @param s input UTF8 string
 * @param errors how to handle invalid UTF8 encodings
 * @return a upper-case version of the input string
 * @throws RuntimeError if the input is not a valid UTF8 string
 */
std::string upper(std::string_view s, unicode::DecodeErrorStrategy errors = unicode::DecodeErrorStrategy::REPLACE);

/**
 * Splits the string at sequences of whitespace.
 *
 * @param s the string to split
 * @return a vector with elements split at whitespace
 */
Vector<std::string> split(std::string_view s);

/**
 * Splits the string at occurrences of a separator.
 *
 * @param s the string to split
 * @param sep the string to split at
 * @return a vector with elements split at the separator
 */
Vector<std::string> split(std::string_view s, std::string_view sep);

/**
 * Splits the string (only) at the first sequence of whitespace, returning exactly two parts.
 * If whitespace does not occur, then only the first part will be populated.
 *
 * @param s the string to split
 * @return a tuple with elements before and after the separator
 */
std::tuple<std::string, std::string> split1(const std::string& s);

/**
 * Splits the string (only) at the first sequence of a separator, returning exactly two parts.
 * If the separator does not occur, then only the first part will be populated.
 *
 * @param s the string to split
 * @param sep the string to split at the first occurrence
 * @return a tuple with elements before and after the separator
 */
std::tuple<std::string, std::string> split1(const std::string& s, const std::string& sep);

/**
 * Creates a bytes instance from a raw string representation
 * encoded in a specified character set.
 *
 * @param s raw data
 * @param cs character set the raw data is assumed to be encoded in
 * @param errors how to handle errors when decoding the data
 * @return bytes instances encoding *s* in character set *cs*
 */
rt::Bytes encode(std::string s, unicode::Charset cs,
                 unicode::DecodeErrorStrategy errors = unicode::DecodeErrorStrategy::REPLACE);

} // namespace string

namespace detail::adl {
inline std::string to_string(const std::string& x, adl::tag /*unused*/) {
    return fmt("\"%s\"", escapeUTF8(x, render_style::UTF8::EscapeQuotes | render_style::UTF8::NoEscapeHex));
}

inline std::string to_string(std::string_view x, adl::tag /*unused*/) {
    return fmt("\"%s\"", escapeUTF8(x, render_style::UTF8::EscapeQuotes | render_style::UTF8::NoEscapeHex));
}

template<typename CharT, size_t N>
inline std::string to_string(const CharT (&x)[N], adl::tag /*unused*/) {
    return fmt("\"%s\"", escapeUTF8(x, render_style::UTF8::EscapeQuotes | render_style::UTF8::NoEscapeHex));
}

} // namespace detail::adl

template<>
inline std::string detail::to_string_for_print<std::string>(const std::string& x) {
    return escapeUTF8(x, render_style::UTF8::NoEscapeHex | render_style::UTF8::NoEscapeControl |
                             render_style::UTF8::NoEscapeBackslash);
}

template<>
inline std::string detail::to_string_for_print<std::string_view>(const std::string_view& x) {
    return escapeUTF8(x, render_style::UTF8::NoEscapeHex | render_style::UTF8::NoEscapeControl |
                             render_style::UTF8::NoEscapeBackslash);
}

// Specialization for string literals. Since `to_string_for_print` is not
// implemented with ADL like e.g., `to_string` provide an overload for string
// literals. This is needed since we cannot partially specialize
// `to_string_for_print`.
template<typename CharT, size_t N>
inline std::string to_string_for_print(const CharT (&x)[N]) {
    return x;
}

} // namespace hilti::rt
