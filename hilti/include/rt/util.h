// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <cxxabi.h>

#include <list>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <hilti/rt/autogen/config.h>
#include <hilti/rt/exception.h>
#include <hilti/rt/result.h>
#include <hilti/rt/types/set_fwd.h>
#include <hilti/rt/types/time.h>
#include <hilti/rt/types/vector_fwd.h>

#ifdef CXX_FILESYSTEM_IS_EXPERIMENTAL
#include <experimental/filesystem>
namespace std {
using namespace experimental;
} // namespace std
#else
#include <filesystem>
#endif

namespace hilti::rt {

void internalError(const std::string& msg) __attribute__((noreturn));

} // namespace hilti::rt

#undef TINYFORMAT_ERROR
#define TINYFORMAT_ERROR(reason) throw ::hilti::rt::FormattingError(reason)
#include <hilti/rt/extension-points.h>
#include <hilti/rt/fmt.h>

#include <hilti/3rdparty/tinyformat/tinyformat.h>

namespace hilti::rt {

/** Returns a string identifying the version of the runtime library. */
extern std::string version();

/** Returns true if called for a debug version of the runtime library. */
extern bool isDebugVersion();

/** Dumps a backtrack to stderr and then aborts execution. */
extern void abort_with_backtrace() __attribute__((noreturn));

/** Aborts with an internal error saying we should not be where we are. */
extern void cannot_be_reached() __attribute__((noreturn));

/** Statistics about the current state of memory allocations. */
struct MemoryStatistics {
    // Note when changing this, update `memory_statistics()`.
    uint64_t memory_heap;   //< current size of heap in bytes
    uint64_t num_fibers;    //< number of fibers currently in use
    uint64_t max_fibers;    //< high-water mark for number of fibers in use
    uint64_t cached_fibers; //< number of fibers currently cached for reuse
};

/** Returns statistics about the current state of memory allocations. */
MemoryStatistics memory_statistics();

/**
 * Creates a temporary file in the system temporary directory.
 *
 * @param prefix prefix to use for the file's basename
 * @return a valid path or an error
 * */
hilti::rt::Result<std::filesystem::path> createTemporaryFile(const std::string& prefix = "");

/** Turns a path into an absolute path with all dots removed. */
std::filesystem::path normalizePath(const std::filesystem::path& p);

/**
 * Returns a string view with all trailing characters of a given set removed.
 *
 * \note This function is not UTF8-aware.
 */
inline std::string_view rtrim(std::string_view s, const std::string& chars) noexcept {
    s.remove_suffix(s.size() -
                    [](size_t pos) { return pos != std::string_view::npos ? pos + 1 : 0; }(s.find_last_not_of(chars)));
    return s;
}

/**
 * Returns a string view with all leading characters of a given set removed.
 *
 * \note This function is not UTF8-aware.
 */
inline std::string_view ltrim(std::string_view s, const std::string& chars) noexcept {
    s.remove_prefix(std::min(s.find_first_not_of(chars), s.size()));
    return s;
}

/**
 * Returns a string view with all leading & trailing characters of a given
 * set removed.
 *
 * \note This function is not UTF8-aware.
 */
inline std::string_view trim(std::string_view s, const std::string& chars) noexcept {
    return ltrim(rtrim(s, chars), chars);
}

namespace detail {
constexpr char whitespace_chars[] = " \t\f\v\n\r";
} // namespace detail

/**
 * Returns a string view with all trailing white space removed.
 *
 * \note This function is not UTF8-aware.
 */
inline std::string_view rtrim(std::string_view s) noexcept { return rtrim(s, detail::whitespace_chars); }

/**
 * Returns a string view with all leading white space removed.
 *
 * \note This function is not UTF8-aware.
 */
inline std::string_view ltrim(std::string_view s) noexcept { return ltrim(s, detail::whitespace_chars); }

/**
 * Returns a string view with all leading & trailing white space removed.
 *
 * \note This function is not UTF8-aware.
 */
inline std::string_view trim(std::string_view s) noexcept { return trim(s, detail::whitespace_chars); }

/**
 * Splits a string at all occurrences of a delimiter. Successive occurrences
 * of the delimiter will be split into multiple pieces.
 *
 * \note This function is not UTF8-aware.
 */
std::vector<std::string_view> split(std::string_view s, std::string_view delim);

/**
 * Splits a string at all occurrences of successive white space.
 *
 * \note This function is not UTF8-aware.
 */
std::vector<std::string_view> split(std::string_view s);

/**
 * Splits a string once at the 1st occurrence of successive whitespace. Leaves
 * the 2nd element of the result pair unset if whitespace does not occur.
 *
 * \note This function is not UTF8-aware.
 */
extern std::pair<std::string, std::string> split1(std::string s);

/**
 * Splits a string once at the last occurrence of successive whitespace. Leaves
 * the 2nd element of the result pair unset if whitespace does not occur.

 * \note This function is not UTF8-aware.
 */
extern std::pair<std::string, std::string> rsplit1(std::string s);

/**
 * Splits a string once at the 1st occurrence of a delimiter. Leaves the 2nd
 * element of the result pair unset if the delimiter does not occur.
 *
 * \note This function is not UTF8-aware.
 */
extern std::pair<std::string, std::string> split1(std::string s, const std::string& delim);

/**
 * Splits a string once at the last occurrence of a delimiter. Leaves the 1st
 * element of the result pair unset if the delimiter does not occur.
 *
 * \note This function is not UTF8-aware.
 */
extern std::pair<std::string, std::string> rsplit1(std::string s, const std::string& delim);

/**
 * Replaces all occurrences of one string with another.
 *
 * \note This function is not UTF8-aware.
 */
std::string replace(std::string s, std::string_view o, std::string_view n);

/**
 * Returns true if a string begins with another.
 *
 * \note This function is not UTF8-aware.
 */
inline bool startsWith(const std::string& s, const std::string& prefix) { return s.find(prefix) == 0; }

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

/*
 * Expands escape sequences in a UTF8 string. The following escape sequences
 * are supported:
 *
 *    ============   ============================
 *    Escape         Result
 *    ============   ============================
 *    \\             Backslash
 *    \\n            Line feed
 *    \\r            Carriage return
 *    \\t            Tabulator
 *    \\uXXXX        16-bit Unicode codepoint
 *    \\UXXXXXXXX    32-bit Unicode codepoint
 *    \\xXX          8-bit hex value
 *    ============   ============================
 *
 * @param str string to expand
 * @return A UTF8 string with escape sequences expanded
 */
std::string expandEscapes(std::string s);

/*
 * Escapes non-printable characters in a raw string. This produces a new
 * string that can be reverted by expandEscapes().
 *
 * @param str string to escape
 * @param escape_quotes if true, also escapes quotes characters
 * @param use_octal use `\NNN` instead of `\XX` (needed for C++)
 * @return escaped string
 *
 * \todo This is getting messy; should use enums instead of booleans.
 */
std::string escapeBytes(std::string_view s, bool escape_quotes = false, bool use_octal = false);

/*
 * Escapes non-printable and control characters in an UTF8 string. This
 * produces a new string that can be reverted by expandEscapes().
 *
 * @param str string to escape
 * @param escape_quotes if true, also escapes quotes characters
 * @param escape_control if false, do not escape control characters
 * @param keep_hex if true, do not escape our custom "\xYY" escape codes
 * @return escaped std::string
 *
 * \todo This is getting messy; should use enums instead of booleans.
 */
std::string escapeUTF8(std::string_view s, bool escape_quotes = false, bool escape_control = true,
                       bool keep_hex = false);

/**
 * Joins elements of a container into a string, using a specified delimiter
 * to separate them.
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

/** Applies a function to each element of a vector, returning a new
    vector with the results.
 */
template<typename X, typename F>
auto transform(const std::vector<X>& x, F f) {
    using Y = typename std::result_of<F(X&)>::type;
    std::vector<Y> y;
    y.reserve(x.size());
    for ( const auto& i : x )
        y.emplace_back(f(i));
    return y;
}

/** Applies a function to each element of a list, returning a new
    vector with the results.
 */
template<typename X, typename F>
auto transform(const std::list<X>& x, F f) {
    using Y = typename std::result_of<F(X&)>::type;
    std::vector<Y> y;
    y.reserve(x.size());
    for ( const auto& i : x )
        y.emplace_back(f(i));
    return y;
}

/** Applies a function to each element of a set, returning a new
    vector with the results.
 */
template<typename X, typename F>
auto transform(const std::set<X>& x, F f) {
    using Y = typename std::result_of<F(X&)>::type;
    std::set<Y> y;
    for ( const auto& i : x )
        y.insert(f(i));
    return y;
}

/** Applies a function to each element of a `rt::Set`. */
template<typename X, typename F>
auto transform(const Set<X>& x, F f) {
    using Y = typename std::result_of<F(X&)>::type;
    hilti::rt::Set<Y> y;
    for ( const auto& i : x )
        y.insert(f(i));
    return y;
}

/** Applies a function to each element of a `rt::Vector`. */
template<typename X, typename Allocator, typename F>
auto transform(const Vector<X, Allocator>& x, F f) {
    using Y = typename std::result_of<F(X&)>::type;
    Vector<Y> y;
    std::transform(x.begin(), x.end(), std::back_inserter(y), [&](const auto& value) { return f(value); });
    return y;
}

class OutOfRange;

/**
 * Parses a numerical value from a character sequence into an
 * integer. Character sequences can start with `+` or `-` to
 * denote the sign.
 *
 * Users should check the returned iterator to detect how many
 * characters were extracted. If the returned iterator is
 * different from `s` the extracted numerical value was stored in
 * the memory pointed to by `result`; otherwise `result` remains
 * unchanged.
 *
 * @pre The input sequence must not be empty, i.e., we require `s != e`.
 * @pre Base must be in the inclusive range [2, 36].
 *
 * @par s beginning of the input range.
 * @par e end of the input range.
 * @par base base of the input range.
 * @par result address of the memory location to used for storing
 *     a possible parsed result.
 * @return iterator to the first character not used in value
 *     extraction.
 */
template<class Iter, typename Result>
inline Iter atoi_n(Iter s, Iter e, int base, Result* result) {
    if ( base < 2 || base > 36 )
        throw OutOfRange("base for numerical conversion must be between 2 and 36");

    if ( s == e )
        throw InvalidArgument("cannot decode from empty range");

    std::optional<Result> n = std::nullopt;
    bool neg = false;
    auto it = s;

    if ( *it == '-' ) {
        neg = true;
        ++it;
    }
    else if ( *it == '+' ) {
        neg = false;
        ++it;
    }

    for ( ; it != e; ++it ) {
        auto c = *it;

        Result d;
        if ( c >= '0' && c < '0' + base )
            d = c - '0';
        else if ( c >= 'a' && c < 'a' - 10 + base )
            d = c - 'a' + 10;
        else if ( c >= 'A' && c < 'A' - 10 + base )
            d = c - 'A' + 10;
        else
            break;

        n = n.value_or(Result()) * base + d;
    }

    if ( ! n )
        return s;

    s = it;

    if ( neg )
        *result = -*n;
    else
        *result = *n;

    return s;
}

/**
 * Computes integer powers
 */
template<typename I1, typename I2>
inline I1 pow(I1 base, I2 exp) {
    I1 x = 1;

    while ( exp ) {
        if ( exp & 1 )
            x *= base;

        exp >>= 1;
        base *= base;
    }

    return x;
}

// Tuple for-each, from
// https://stackoverflow.com/questions/40212085/type-erasure-for-objects-containing-a-stdtuple-in-c11
namespace detail {
template<typename T, typename F, std::size_t... Is>
constexpr auto map_tuple(T&& tup, F& f, std::index_sequence<Is...> /*unused*/) {
    return std::make_tuple(f(std::get<Is>(std::forward<T>(tup)))...);
}

template<typename T, std::size_t... Is>
auto join_tuple(T&& tup, std::index_sequence<Is...> /*unused*/) {
    std::vector<std::string> x = {rt::to_string(std::get<Is>(std::forward<T>(tup)))...};
    return join(x, ", ");
}

template<typename T, std::size_t... Is>
auto join_tuple_for_print(T&& tup, std::index_sequence<Is...> /*unused*/) {
    std::vector<std::string> x = {rt::to_string_for_print(std::get<Is>(std::forward<T>(tup)))...};
    return join(x, ", ");
}
} // namespace detail

/** Generic tuple for-each that runs a callback for each element. */
template<typename F, std::size_t I = 0, typename... Ts>
void tuple_for_each(const std::tuple<Ts...>& tup, F func) {
    if constexpr ( I == sizeof...(Ts) )
        return;
    else {
        func(std::get<I>(tup));
        tuple_for_each<F, I + 1>(tup, func);
    }
}

/**
 * Applies a transformation function to each element of a tuple, returning a
 * new tuple.
 */
template<typename T, typename F, std::size_t TupSize = std::tuple_size_v<std::decay_t<T>>>
constexpr auto map_tuple(T&& tup, F f) {
    return detail::map_tuple(std::forward<T>(tup), f, std::make_index_sequence<TupSize>{});
}

/**
 * Converts a tuple's elements into string representations and then
 * concatenates those with separating commas.  This version converts the
 * tuple elements into strings using HILTI's standard rendering (which, e.g.,
 * means that strings will be surrounded by quotes).
 */
template<typename T, std::size_t TupSize = std::tuple_size_v<std::decay_t<T>>>
auto join_tuple(T&& tup) {
    return detail::join_tuple(std::forward<T>(tup), std::make_index_sequence<TupSize>{});
}

/**
 * Converts a tuple's elements into string representations and then
 * concatenates those with separating commas. This version converts the tuple
 * elements into strings as if they were given to a HILTI `print` statements
 * (which, e.g., means that top-level strings won't be surrounded by quotes).
 */
template<typename T, std::size_t TupSize = std::tuple_size_v<std::decay_t<T>>>
auto join_tuple_for_print(T&& tup) {
    return detail::join_tuple_for_print(std::forward<T>(tup), std::make_index_sequence<TupSize>{});
}

template<typename>
struct is_tuple : std::false_type {};

/** Checks if a type is a tuple. */
template<typename... T>
struct is_tuple<std::tuple<T...>> : std::true_type {};

/** Available byte orders. */
enum class ByteOrder { Little, Big, Network, Host, Undef = -1 };

/**
 * Returns the byte order of the system we're running on. The result is
 * either `ByteOrder::Little` or `ByteOrder::Big`.
 */
extern ByteOrder systemByteOrder();

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
 */
std::string strftime(const std::string& format, const Time& time);

} // namespace hilti::rt
