// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <cxxabi.h>

#include <algorithm>
#include <climits>
#include <cmath>
#include <functional>
#include <initializer_list>
#include <iostream>
#include <list>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <vector>

#include <hilti/rt/filesystem.h>
#include <hilti/rt/unpack.h>
#include <hilti/rt/util.h>

#include <hilti/autogen/config.h>
#include <hilti/base/result.h>

namespace hilti::util::detail {
/** Helper that forwards to `Logger`. */
void __internal_error(const std::string& s);
} // namespace hilti::util::detail

#undef TINYFORMAT_ERROR
#define TINYFORMAT_ERROR(reason) ::util::detail::__internal_error(reason)
#include <hilti/rt/3rdparty/tinyformat/tinyformat.h>

namespace hilti {

struct Configuration;

/**
 * Helper macro to mark variables that are intentionally unused. This
 * silences the compiler warning. From
 * http://stackoverflow.com/questions/777261/avoiding-unused-variables-warnings-when-using-assert-in-a-release-build
 */
#define _UNUSED(x) ((void)(x));

/** Tests if class is derived from another. */
#define IF_DERIVED_FROM(t, cls) typename std::enable_if_t<std::is_base_of<cls, t>::value>* = nullptr

/** Tests if class is not  derived from another. */
#define IF_NOT_DERIVED_FROM(t, cls) typename std::enable_if_t<! std::is_base_of<cls, t>::value>* = nullptr

/** Tests if two are class are the same. */
#define IF_SAME(t, cls) typename std::enable_if_t<std::is_same<cls, t>::value>* = nullptr

/** Tests if two are class are not the same. */
#define IF_NOT_SAME(t, cls) typename std::enable_if_t<! std::is_same<cls, t>::value>* = nullptr

namespace util {

/** Wrapper around the ABI's C++ demangle function. */
using hilti::rt::demangle;

/** Aborts with an internal error saying we should not be where we are. */
extern void cannot_be_reached() __attribute__((noreturn));

/** Returns a type's demangled C++ name. */
template<typename T>
std::string typename_() {
    return demangle(typeid(T).name());
}

/** sprintf-style string formatting. */
template<typename... Args>
std::string fmt(const char* fmt, const Args&... args) {
    return tfm::format(fmt, args...);
}

using hilti::rt::transform; // NOLINT(misc-unused-using-decls)

/** Applies a function to each element of a set, returning a vector with the results. */
template<typename X, typename F>
auto transform_to_vector(const std::set<X>& x, F f) {
    using Y = typename std::invoke_result_t<F, X&>;
    std::vector<Y> y;
    y.reserve(x.size());
    for ( const auto& i : x )
        y.push_back(f(i));
    return y;
}

/** Filters a container through a boolean predicate. */
template<typename C, typename F>
auto filter(const C& x, F f) {
    C y;
    std::copy_if(std::begin(x), std::end(x), std::inserter(y, std::end(y)), f);
    return y;
}

/**
 * Python-style enumerate() that returns an iterable yielding pairs `(index,
 * val)`. From http://reedbeta.com/blog/python-like-enumerate-in-cpp17/.
 */
template<typename T, typename TIter = decltype(std::begin(std::declval<T>())),
         typename = decltype(std::end(std::declval<T>()))>
constexpr auto enumerate(T&& iterable) {
    struct iterator {
        size_t i;
        TIter iter;
        bool operator!=(const iterator& other) const { return iter != other.iter; }
        void operator++() {
            ++i;
            ++iter;
        }
        auto operator*() const { return std::tie(i, *iter); }
    };
    struct iterable_wrapper {
        T iterable;
        auto begin() { return iterator{0, std::begin(iterable)}; }
        auto end() { return iterator{0, std::end(iterable)}; }
    };
    return iterable_wrapper{std::forward<T>(iterable)};
}

/** Splits a string at all occurrences of a delimiter. */
extern std::vector<std::string> split(std::string s, const std::string& delim = " ");

/**
 * Splits a string once at the 1st occurrence of a delimiter. Leaves the 2nd
 * element of the result pair unset if the delimiter does not occur.
 */
extern std::pair<std::string, std::string> split1(std::string s, const std::string& delim = " ");

/**
 * Splits a string once at the last occurrence of a delimiter. Leaves the 1st
 * element of the result pair unset if the delimiter does not occur.
 */
extern std::pair<std::string, std::string> rsplit1(std::string s, const std::string& delim = " ");

/**
 * Returns a subrange of a vector, specified through zero-based indices. If
 * indices are out of range, they are cut back to start/end of input.
 *
 * @param v vector to slice
 * @param begin 1st index; if negative, counts from end Python-style
 * @param end one beyond last index; if negative, counts from end Python-style
 */
template<typename T>
std::vector<T> slice(const std::vector<T>& v, int begin, int end = -1) {
    if ( begin < 0 )
        begin = v.size() + begin;

    if ( static_cast<size_t>(begin) > v.size() )
        return {};

    if ( end < 0 )
        end = v.size() + end + 1;

    if ( begin < 0 )
        begin = 0;

    if ( end < 0 )
        end = 0;

    if ( static_cast<size_t>(end) > v.size() )
        end = v.size();

    return std::vector<T>(v.begin() + begin, v.begin() + end);
}

/**
 * Joins elements of a vector into a string, using a given delimiter to
 * separate them.
 */
template<typename T>
std::string join(const T& l, const std::string& delim = "") {
    std::string result;
    bool first = true;

    for ( const auto& i : l ) {
        if ( not first )
            result += delim;

        result += std::string(i);
        first = false;
    }

    return result;
}

/**
 * Joins elements of an initializer list into a string, using a given
 * delimiter to separate them.
 */
template<typename T>
std::string join(const std::initializer_list<T>& l, const std::string& delim = "") {
    std::string result;
    bool first = true;

    for ( const auto& i : l ) {
        if ( not first )
            result += delim;
        result += std::string(i);
        first = false;
    }

    return result;
}

/**
 * Joins elements of an iterable range into a string, using a given delimiter
 * to separate then.
 */
template<typename iterator>
std::string join(const iterator& begin, const iterator& end, const std::string& delim = "") {
    std::string result;
    bool first = true;

    for ( iterator i = begin; i != end; i++ ) {
        if ( not first )
            result += delim;
        result += std::string(*i);
        first = false;
    }

    return result;
}


/**
 * Splits a string into white-space-delimited pieces, prefixes each piece
 * with another string, and then joins it all back together.
 *
 * Optionally filters out strings with a specific tag: If an inclusion tag is
 * specified, each string is inspected if it starts with ``!<tag>!``. If it
 * does, it's only included if ``tag == include_tag``. Strings without tags
 * are always included.
 *
 * \note This is primarily a helper for creating our configuration files from
 * CMake input.

 * @param in string to split
 * @param prefix prefix to add to each part
 * @param include_tag filter tags
 * @return reassembled string with parts prefixed
 */
extern std::string prefixParts(const std::string& in, const std::string& prefix, const std::string& include_tag = "");

/**
 * For each string in a vector, splits them into white-space delimited
 * pieces, then joins all pieces into a single new vector of strings.
 *
 * \note This is primarily a helper for creating our configuration files from
 * CMake input.
 *
 * @param in vector with strings to each splits
 * @return reassembled vector
 */
extern std::vector<std::string> flattenParts(const std::vector<std::string>& in);

/** Replaces all occurrences of one string with another. */
extern std::string replace(const std::string& s, const std::string& o, const std::string& n);

/** Returns a lower-case version of a string. */
extern std::string tolower(const std::string& s);

/** Returns a upper-case version of a string. */
extern std::string toupper(const std::string& s);

/** Returns a string with all leading & trailing white space removed. */
extern std::string trim(const std::string& s);

/** Returns a string with all trailing white space removed. */
extern std::string rtrim(const std::string& s);

/** Returns a string with all leading white space removed. */
extern std::string ltrim(const std::string& s);

/** Returns true if a string begins with another. */
inline bool startsWith(const std::string& s, const std::string& prefix) { return s.find(prefix) == 0; }

/** Returns true if a string ends with another. */
extern bool endsWith(const std::string& s, const std::string& suffix);

/**  Returns a simple (non-crypto) hash value of a std::string. */
extern uint64_t hash(const std::string& str);

/** Returns a simple (non-crypto) hash value of a memory block. */
extern uint64_t hash(const char* data, size_t len);

/**
 * Returns the valid value range for a signed integer of a given width.
 * Supports only standard widths 8/16/32/64.
 */
constexpr std::pair<intmax_t, intmax_t> signed_integer_range(int width) {
    switch ( width ) {
        case 8: return std::make_pair(INT8_MIN, INT8_MAX);
        case 16: return std::make_pair(INT16_MIN, INT16_MAX);
        case 32: return std::make_pair(INT32_MIN, INT32_MAX);
        case 64: return std::make_pair(INT64_MIN, INT64_MAX);
        default: throw std::out_of_range("unsupported integer width");
    }
}

/**
 * Returns the valid value range for an unsigned integer of a given width.
 * Supports only standard widths 8/16/32/64.
 */
constexpr std::pair<uintmax_t, uintmax_t> unsigned_integer_range(int width) {
    switch ( width ) {
        case 8: return std::make_pair(0, UINT8_MAX);
        case 16: return std::make_pair(0, UINT16_MAX);
        case 32: return std::make_pair(0, UINT32_MAX);
        case 64: return std::make_pair(0, UINT64_MAX);
        default: throw std::out_of_range("unsupported integer width");
    }
}

/**
 * Converts digits to an unsigned integer relative to a given base.
 *
 * @param dgts: null-terminated chars: decimal digits, hexits or base-n-digits
 * @param base: base to use {0,2,3,...,36} (base 0 auto-detects like strtoull).
 * @param handler: an error-handling function object or lambda.
 */
template<typename Error>
uint64_t chars_to_uint64(const char* dgts, int base, Error handler) {
    errno = 0;
    char* cp;
    auto u = strtoull(dgts, &cp, base);
    if ( cp == dgts || *cp != '\0' || (u == ULONG_MAX && errno == ERANGE) ) {
        errno = 0;
        handler();
    }
    return u;
};

/**
 * Converts digits to double precision floating point.
 *
 * @param dgts: null-terminated chars: decimal floating-point or hexfloat format.
 * @param handler: an error-handling function object or lambda.
 */
template<typename Error>
double chars_to_double(const char* dgts, Error handler) {
    errno = 0;
    char* cp;
    auto d = strtod(dgts, &cp);
    if ( cp == dgts || *cp != '\0' || (d == HUGE_VAL && errno == ERANGE) ) {
        errno = 0;
        handler();
    }

    return d;
};

/**
 * Converts an integer into a string relative to a given base.
 *
 * @param value: value to convert
 * @param base: base to use
 * @param n: The maximum number of characters to include. If the final string would
 * be longer than this, it's cut off. If smaller than zero, includes all.
 *
 * @return converted string
 */
extern std::string uitoa_n(uint64_t value, unsigned int base, int n = -1);

using hilti::rt::escapeBytes;
using hilti::rt::escapeUTF8;    // NOLINT(misc-unused-using-decls)
using hilti::rt::expandEscapes; // NOLINT(misc-unused-using-decls)

/**
 * Wrapper for `escapeBytes` that produces a valid C++ string literal.
 *
 * @param s string to escape
 * @return escaped std::string
 *
 */
inline std::string escapeBytesForCxx(std::string_view s) { return escapeBytes(s, true, true); }

/**
 * Turns an arbitrary string into something that can be used as C-level
 * identifier.
 *
 * @param s string to convert.
 * @param ensure_non_keyword if true, the returned ID will be expanded to make
 * sure it won't accidentally match a compiler keyword.
 * @return valid C identifier
 */
extern std::string toIdentifier(const std::string& s, bool ensure_non_keyword = false);

/** Returns the current time in seconds since the epoch. */
extern double currentTime();

/** Search a file name inside a given set of paths. */
extern hilti::Result<hilti::rt::filesystem::path> findInPaths(const hilti::rt::filesystem::path& file,
                                                              const std::vector<hilti::rt::filesystem::path>& paths);

/** Turns a path into an absolute path with all dots removed. */
using hilti::rt::normalizePath; // NOLINT(misc-unused-using-decls)

/**
 * Creates a temporary file in the system temporary directory.
 *
 * @param prefix prefix to use for the file's basename
 * @return a valid path or an error
 * */
using hilti::rt::createTemporaryFile; // NOLINT(misc-unused-using-decls)

/** Returns the path of the current executable. */
hilti::rt::filesystem::path currentExecutable();

/** Dumps a backtrace to stderr and then aborts execution. */
[[noreturn]] extern void abort_with_backtrace();

/** Parses an string into an integer value. */
template<class Iter, typename Result>
inline auto atoi_n(Iter s, Iter e, int base, Result* result) {
    return hilti::rt::atoi_n(s, e, base, result);
}

/**
 * Pairs up the elements of two lists.
 *
 * From http://stackoverflow.com/questions/10420380/c-zip-variadic-templates.
 */
template<typename A, typename B>
std::list<std::pair<A, B>> zip2(const std::list<A>& lhs, const std::list<B>& rhs) {
    std::list<std::pair<A, B>> result;
    for ( std::pair<typename std::list<A>::const_iterator, typename std::list<B>::const_iterator> iter =
              std::pair<typename std::list<A>::const_iterator, typename std::list<B>::const_iterator>(lhs.cbegin(),
                                                                                                      rhs.cbegin());
          iter.first != lhs.end() and iter.second != rhs.end(); ++iter.first, ++iter.second )
        result.emplace_back(*iter.first, *iter.second);
    return result;
}

/**
 * Pairs up the elements of two vectors.
 *
 * From http://stackoverflow.com/questions/10420380/c-zip-variadic-templates.
 */
template<typename A, typename B>
std::vector<std::pair<A, B>> zip2(const std::vector<A>& lhs, const std::vector<B>& rhs) {
    std::vector<std::pair<A, B>> result;
    for ( std::pair<typename std::vector<A>::const_iterator, typename std::vector<B>::const_iterator> iter =
              std::pair<typename std::vector<A>::const_iterator, typename std::vector<B>::const_iterator>(lhs.cbegin(),
                                                                                                          rhs.cbegin());
          iter.first != lhs.end() and iter.second != rhs.end(); ++iter.first, ++iter.second )
        result.emplace_back(*iter.first, *iter.second);
    return result;
}

/** Returns the keys of a map as a set. */
template<typename A, typename B>
std::set<A> map_keys(const std::map<A, B>& m) {
    std::set<A> l;

    for ( const auto& i : m )
        l.insert(i.first);

    return l;
}

/** Returns the values of a map as a set. */
template<typename A, typename B>
std::set<B> map_values(const std::map<A, B>& m) {
    std::set<B> l;

    for ( const auto& i : m )
        l.insert(i.second);

    return l;
}

/** Returns the keys of a map as a set. */
template<typename A, typename B>
std::set<A> map_keys(const std::unordered_map<A, B>& m) {
    std::set<A> l;

    for ( const auto& i : m )
        l.insert(i.first);

    return l;
}

/** Returns the values of a map as a set. */
template<typename A, typename B>
std::set<B> map_values(const std::unordered_map<A, B>& m) {
    std::set<B> l;

    for ( const auto& i : m )
        l.insert(i.second);

    return l;
}

/** Returns the difference of two sets. This is a convenience wrapper around std::set_difference. */
template<typename A, typename Compare = std::less<A>>
std::set<A, Compare> set_difference(const std::set<A, Compare>& a, const std::set<A, Compare>& b) {
    std::set<A, Compare> r;
    std::set_difference(a.begin(), a.end(), b.begin(), b.end(), std::inserter(r, r.end()), Compare());
    return r;
}

/** Returns the intersection of two sets. This is a convenience wrapper around std::set_intersection. */
template<typename A, typename Compare = std::less<A>>
std::set<A, Compare> set_intersection(std::set<A, Compare>& a, std::set<A, Compare>& b) {
    std::set<A, Compare> r;
    std::set_intersection(a.begin(), a.end(), b.begin(), b.end(), std::inserter(r, r.end()), Compare());
    return r;
}

/** Returns the union of two sets. This is a convenience wrapper around std::set_union. */
template<typename A, typename Compare = std::less<A>>
std::set<A, Compare> set_union(const std::set<A, Compare>& a, const std::set<A, Compare>& b) {
    std::set<A, Compare> r;
    std::set_union(a.begin(), a.end(), b.begin(), b.end(), std::inserter(r, r.end()), Compare());
    return r;
}

/** Concatenates two vectors into a new one. */
template<typename T>
std::vector<T> concat(std::vector<T> v1, const std::vector<T>& v2) {
    v1.reserve(v1.size() + v2.size());
    v1.insert(v1.end(), v2.begin(), v2.end());
    return v1;
}

/** Appends a vector to another one. */
template<typename T>
std::vector<T>& append(std::vector<T>& v1, const std::vector<T>& v2) {
    v1.reserve(v1.size() + v2.size());
    v1.insert(v1.end(), v2.begin(), v2.end());
    return v1;
}

/** Remov duplicates from a vector without changing order. */
template<typename T>
std::vector<T> remove_duplicates(std::vector<T> v) {
    std::set<T> seen;
    std::vector<T> out;

    for ( auto&& i : v ) {
        if ( seen.find(i) != seen.end() )
            continue;

        seen.insert(i);
        out.emplace_back(std::move(i));
    }

    return out;
}

/**
 * Given an associative container and an index hint, returns a new index
 * value that doesn't exist in the container yet. If the hint itself doesn't
 * exist yet, it's returned directly.
 */
template<typename T>
std::string uniqueIndex(const T& c, std::string hint) {
    if ( c.find(hint) == c.end() )
        return hint;

    std::string idx;
    int cnt = 1;

    while ( true ) {
        std::string idx = fmt("%s.%d", hint, ++cnt);
        if ( c.find(idx) == c.end() )
            return idx;
    }
}

/** Copies the content of one stream into another one. Returns true if successful. */
inline bool copyStream(std::istream& in, std::ostream& out) {
    char buffer[4096];
    while ( in.good() ) {
        in.read(buffer, sizeof(buffer));
        out.write(buffer, sizeof(buffer));
    }

    return in.eof();
}

namespace enum_ {

/** Helper class mapping an enum value to a string label. */
template<typename E>
struct Value {
    E value;
    const char* name;
};

/**
 * Converts a string label to an enumerator value, based on a mapping table.
 *
 * @tparam Enum enum type that the mapping operation applies to
 * @tparam Size number of enumerators that the enum type has
 * @param name name to convert into enumerator
 * @param values array of enumerator-to-string mappings
 *
 * @throws `std::out_of_range` if *name* is not found in *values*
 */
template<typename Enum, std::size_t Size>
constexpr auto from_string(const std::string_view name, const Value<Enum> (&values)[Size]) {
    for ( const auto& v : values )
        if ( v.name == name )
            return v.value;

    throw std::out_of_range(name.data());
};

/**
 * Converts an enumerator value to string label, based on a mapping table.
 *
 * @tparam Enum enum type that the mapping operation applies to
 * @tparam Size number of enumerators the enum type has
 * @param value enumerator to convert into string
 * @param values array of enumerator-to-string mappings
 *
 * @throws `std::out_of_range` if *value* is not found in *values*
 */
template<typename Enum, std::size_t Size>
constexpr auto to_string(Enum value, const Value<Enum> (&values)[Size]) {
    for ( const auto& v : values )
        if ( v.value == value )
            return v.name;

    throw std::out_of_range(std::to_string(static_cast<int>(value)));
};

} // namespace enum_

/** Computes path to directory for cached artifacts
 *
 * @param configuration the configuration to use
 * @return a valid path to the directory or nothing
 * \note While the returned path is valid, it might not exist yet.
 */
std::optional<hilti::rt::filesystem::path> cacheDirectory(const hilti::Configuration& configuration);

} // namespace util

} // namespace hilti
