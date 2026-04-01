// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <string_view>

#include <hilti/rt/extension-points.h>
#include <hilti/rt/safe-int.h>
#include <hilti/rt/types/optional.h>
#include <hilti/rt/types/result.h>
#include <hilti/rt/types/tuple.h>
#include <hilti/rt/types/vector.h>
#include <hilti/rt/unicode.h>
#include <hilti/rt/util.h>

namespace hilti::rt {

class Bytes;

/**
 * HILTI's `string` is a `std::string`-like type for wrapping raw bytes with
 * additional safety guarantees.
 *
 * If not otherwise specified, member functions have the semantics of
 * `std::string` member functions. Note, however, that by design this type does
 * not convert to/from `std::string` to avoid mixing up the two accidentally in
 * runtime code. Instead, `std::string_view` can serve as a go-between type for
 * conversions.
 */
class String : protected std::string {
public:
    using S = std::string;

    /** Creates an empty string. */
    String() = default;

    /** Creates a string from a standard string view. */
    String(std::string_view s) : S(s) {}

    String(const String&) = default;
    String(String&&) = default;

    String& operator=(std::string_view sv) {
        S::operator=(sv);
        return *this;
    }

    String& operator=(const String&) = default;
    String& operator=(String&&) = default;

    /** Returns the string's data as a standard string view. */
    auto str() const { return std::string_view(data(), size()); }

    /** Implicitly converts the string to a standard string view. */
    operator std::string_view() const { return str(); } // NOLINT(google-explicit-constructor)

    /**
     * Returns a substring of the string.
     *
     * @param pos the position of the first character to include in the substring
     * @param count the number of characters to include in the substring, or
     * `npos` to include all characters until the end of the string
     */

    String& operator+=(const String& b) {
        append(b);
        return *this;
    }

    String& operator+=(std::string_view b) {
        append(b);
        return *this;
    }


    // Methods borrowed from `std::string`.
    using S::empty;
    using S::find;
    using S::npos;
    using S::size;

    friend bool operator==(const String& a, const String& b) { return a.str() == b.str(); }
    friend bool operator==(const String& a, std::string_view b) { return a.str() == b; }
    friend bool operator==(const String& a, const char* b) { return a.str() == std::string_view(b); }

    friend bool operator<(const String& a, const String& b) { return a.str() < b.str(); }
    friend bool operator<(const String& a, std::string_view b) { return a.str() < b; }
    friend bool operator<(const String& a, const char* b) { return a.str() < b; }

    friend String operator+(const String& a, const String& b) {
        String r;
        r.reserve(a.size() + b.size());
        r.append(a);
        r.append(b);
        return r;
    }

    friend String operator+(const String& a, std::string_view b) {
        String r;
        r.reserve(a.size() + b.size());
        r.append(a);
        r.append(b);
        return r;
    }
};

namespace string {

/**
 * Computes the length of a UTF8 string in number of codepoints.
 *
 * @param s input UTF8 string
 * @param errors how to handle invalid UTF8 encodings
 * @return the length of the input string
 * @throws RuntimeError if the input is not a valid UTF8 string
 */
integer::safe<uint64_t> size(const String& s,
                             unicode::DecodeErrorStrategy errors = unicode::DecodeErrorStrategy::REPLACE);

/**
 * Computes a lower-case version of an UTF8 string.
 *
 * @param s input UTF8 string
 * @param errors how to handle invalid UTF8 encodings
 * @return a lower-case version of the input string
 * @throws RuntimeError if the input is not a valid UTF8 string
 */
String lower(const String& s, unicode::DecodeErrorStrategy errors = unicode::DecodeErrorStrategy::REPLACE);

/**
 * Computes a upper-case version of an UTF8 string.
 *
 * @param s input UTF8 string
 * @param errors how to handle invalid UTF8 encodings
 * @return a upper-case version of the input string
 * @throws RuntimeError if the input is not a valid UTF8 string
 */
String upper(const String& s, unicode::DecodeErrorStrategy errors = unicode::DecodeErrorStrategy::REPLACE);

/**
 * Splits the string at sequences of whitespace.
 *
 * @param s the string to split
 * @return a vector with elements split at whitespace
 */
Vector<String> split(const String& s);

/**
 * Splits the string at occurrences of a separator.
 *
 * @param s the string to split
 * @param sep the string to split at
 * @return a vector with elements split at the separator
 */
Vector<String> split(const String& s, const String& sep);

/**
 * Splits the string (only) at the first sequence of whitespace, returning exactly two parts.
 * If whitespace does not occur, then only the first part will be populated.
 *
 * @param s the string to split
 * @return a tuple with elements before and after the separator
 */
Tuple<String, String> split1(const String& s);

/**
 * Splits the string (only) at the first sequence of a separator, returning exactly two parts.
 * If the separator does not occur, then only the first part will be populated.
 *
 * @param s the string to split
 * @param sep the string to split at the first occurrence
 * @return a tuple with elements before and after the separator
 */
Tuple<String, String> split1(const String& s, const String& sep);

/**
 * Creates a bytes instance from a raw string representation
 * encoded in a specified character set.
 *
 * @param s raw data
 * @param cs character set the raw data is assumed to be encoded in
 * @param errors how to handle errors when decoding the data
 * @return bytes instances encoding *s* in character set *cs*
 */
rt::Bytes encode(const String& s, unicode::Charset cs,
                 unicode::DecodeErrorStrategy errors = unicode::DecodeErrorStrategy::REPLACE);

inline namespace literals {
inline String operator""_hs(const char* s, size_t n) { return String(std::string_view(s, n)); }
} // namespace literals

} // namespace string

namespace detail::adl {

inline std::string to_string(const String& x, adl::tag /*unused*/) {
    return fmt("\"%s\"", escapeUTF8(x.str(), render_style::UTF8::EscapeQuotes | render_style::UTF8::NoEscapeHex));
}

inline std::string to_string(std::string_view x, adl::tag /*unused*/) {
    return fmt("\"%s\"", escapeUTF8(x, render_style::UTF8::EscapeQuotes | render_style::UTF8::NoEscapeHex));
}

} // namespace detail::adl

inline std::ostream& operator<<(std::ostream& out, const String& x) {
    out << x.str();
    return out;
}

} // namespace hilti::rt

namespace hilti::rt {

template<>
inline std::string detail::to_string_for_print<String>(const String& x) {
    return escapeUTF8(x.str(), render_style::UTF8::NoEscapeHex | render_style::UTF8::NoEscapeControl |
                                   render_style::UTF8::NoEscapeBackslash);
}

template<>
inline std::string detail::to_string_for_print<std::string_view>(const std::string_view& x) {
    return escapeUTF8(x, render_style::UTF8::NoEscapeHex | render_style::UTF8::NoEscapeControl |
                             render_style::UTF8::NoEscapeBackslash);
}

template<>
inline std::string detail::to_string_for_print<Optional<String>>(const Optional<String>& x) {
    return x ? std::string(x->str()) : "(not set)";
}

template<>
inline std::string detail::to_string_for_print<Result<String>>(const Result<String>& x) {
    return x ? std::string(x->str()) : hilti::rt::to_string(x.error());
}

/**
 * Formats a string sprintf-style.
 *
 * \note There's are separate overloads in `fmt.h` that receive and return
 * standard types.
 */
template<typename... Args>
String fmt(const String& fmt_, const Args&... args) {
    return String(hilti::rt::fmt(fmt_.str(), args...));
}

/**
 * Returns the value of an environment variable as a String, if set.
 * Wrapper around the std::string-returning getenv that converts the result.
 *
 * \note This would be better placed in `util.h` but lives here because of the
 * circular include chain caused by the `String` result type.
 */
inline Optional<String> getenv(std::string_view name) {
    if ( auto* x = ::getenv(std::string(name).c_str()) )
        return {std::string(x)};
    else
        return {};
}

/** Formats a time according to user-specified format string.
 *
 * This function uses the currently active locale and timezone to format
 * values. Formatted strings cannot exceed 128 bytes.
 *
 * @param format a POSIX-conformant format string, see
 *        https://pubs.opengroup.org/onlinepubs/009695399/functions/strftime.html
 *        for the available format specifiers
 * @param time timestamp to format
 * @return formatted timestamp
 * @throw `InvalidArgument` if the timestamp could not be formatted
 *
 * \note This would be better placed in `util.h` but lives here because of the
 * circular include chain caused by the `String` result type.
 */
String strftime(std::string_view format, const Time& time);

} // namespace hilti::rt

template<>
struct std::hash<hilti::rt::String> {
    size_t operator()(const hilti::rt::String& s) const noexcept { return std::hash<std::string_view>{}(s); }
};
