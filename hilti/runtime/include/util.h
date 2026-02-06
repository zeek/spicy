// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <cxxabi.h>
#include <unistd.h>

#include <algorithm>
#include <list>
#include <memory>
#include <ranges>
#include <set>
#include <string>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>

#include <hilti/rt/3rdparty/ArticleEnumClass-v2/EnumClass.h>
#include <hilti/rt/exception.h>
#include <hilti/rt/filesystem.h>
#include <hilti/rt/result.h>
#include <hilti/rt/types/set_fwd.h>
#include <hilti/rt/types/time.h>
#include <hilti/rt/types/vector_fwd.h>

/** Helper to construct an internal identifier. */
#define HILTI_INTERNAL(id) _t_##id

/** Helper to construct an internal identifier string. */
#define HILTI_INTERNAL_ID(id) "_t_" id

/** Helper to refer to the generated global namespace. */
#define HILTI_INTERNAL_NS hlt_internal

/** Helper to refer to the generated global namespace. */
#define HILTI_INTERNAL_NS_ID "hlt_internal"

/** Helper to construct an internal identifier string. */
#define HILTI_INTERNAL_GLOBAL(id) hlt_internal_##id

/** Helper to construct an internal identifier string. */
#define HILTI_INTERNAL_GLOBAL_ID(id) "hlt_internal_" id

/**
 * Helper to create runtime type with enum semantics with default value `Undef`.
 *
 * @param name name of the type to create.
 * @param __VA_ARGS__ comma-separated list of enumerator definitions, either
 *        identifier or identifier with initializer.
 */
#define HILTI_RT_ENUM(name, ...)                                                                                       \
    struct name {                                                                                                      \
        enum Value : int64_t { Undef = -1, __VA_ARGS__ };                                                              \
        constexpr name(int64_t value = Undef) noexcept : _value(value) {}                                              \
        friend name Enum(Value value) { return name(value); }                                                          \
        friend constexpr bool operator==(const name& a, const name& b) noexcept { return a.value() == b.value(); }     \
        friend constexpr bool operator!=(const name& a, const name& b) noexcept { return ! (a == b); }                 \
        friend constexpr bool operator<(const name& a, const name& b) noexcept { return a.value() < b.value(); }       \
        constexpr int64_t value() const { return _value; }                                                             \
        int64_t _value;                                                                                                \
    }


/**
 * On Linux `__thread` is faster than C++'s `thread_local`. However, on macOS
 * `__thread` doesn't work. Also see this for a lot of detail:
 * https://maskray.me/blog/2021-02-14-all-about-thread-local-storage.
 */
#if defined(__linux__)
#define HILTI_THREAD_LOCAL __thread
#else
#define HILTI_THREAD_LOCAL thread_local
#endif

namespace hilti::rt {

/** Reports an internal error and aborts execution. */
void internalError(std::string_view msg) __attribute__((noreturn));

} // namespace hilti::rt

#undef TINYFORMAT_ERROR
#define TINYFORMAT_ERROR(reason) throw ::hilti::rt::FormattingError(reason)
#include <hilti/rt/3rdparty/tinyformat/tinyformat.h>
#include <hilti/rt/extension-points.h>
#include <hilti/rt/fmt.h>

namespace hilti::rt {

/** Returns a string identifying the version of the runtime library. */
extern std::string version();

/** Dumps a backtrack to stderr and then aborts execution. */
extern void abort_with_backtrace() __attribute__((noreturn));

/** Aborts with an internal error saying we should not be where we are. */
extern void cannot_be_reached() __attribute__((noreturn));

/** Statistics about resource usage. */
struct ResourceUsage {
    // Note when changing this, update `resource_usage()`.
    double user_time;              //< user time since runtime initialization
    double system_time;            //< system time since runtime initialization
    uint64_t memory_heap;          //< current size of heap in bytes
    uint64_t num_fibers;           //< number of fibers currently in use
    uint64_t max_fibers;           //< high-water mark for number of fibers in use
    uint64_t max_fiber_stack_size; //< global high-water mark for fiber stack size
    uint64_t cached_fibers;        //< number of fibers currently cached for reuse
};

/** Returns statistics about the current resource usage. */
ResourceUsage resource_usage();

/** Returns the value of an environment variable, if set. */
extern Optional<std::string> getenv(const std::string& name);

/**
 * Creates a temporary file in the system temporary directory.
 *
 * @param prefix prefix to use for the file's basename
 * @return a valid path or an error
 * */
hilti::rt::Result<hilti::rt::filesystem::path> createTemporaryFile(const std::string& prefix = "");

/** Turns a path into an absolute path with all dots removed. */
hilti::rt::filesystem::path normalizePath(const hilti::rt::filesystem::path& p);

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
bool startsWith(std::string_view s, std::string_view prefix);

/**
 * Returns true if a string ends with another.
 *
 * \note This function is not UTF8-aware.
 */
bool endsWith(std::string_view s, std::string_view suffix);

/**
 * Python-style enumerate() that returns an iterable yielding pairs `(index,
 * val)`. From http://reedbeta.com/blog/python-like-enumerate-in-cpp17/.
 */
template<typename T, typename TIter = decltype(std::begin(std::declval<T>())),
         typename = decltype(std::end(std::declval<T>()))>
constexpr auto enumerate(T&& iterable) {
    // TODO(C++23): replace callers with `std::views::enumerate` in C++23 and remove this function.
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
std::string expandUTF8Escapes(std::string s);

namespace render_style {

/**
 * Flags specifying escaping style when rendering raw data for printing. The
 * default style renders all non-printable characters as hex escapes (`\xNN`)
 * and escapes backslashes with a second backslash. Any specified flags modify
 * the default style accordingly.
 */
enum class Bytes {
    Default = 0,                    /**< name for unmodified default style */
    EscapeQuotes = (1U << 1U),      /**< escape double quotes with backslashes */
    UseOctal = (1U << 2U),          /**< escape non-printables with `\NNN` instead of `\xNN` */
    NoEscapeBackslash = (1U << 3U), /**< do not escape backslashes */
};

/**
 * Flags specifying escaping style when rendering UTF8 strings for printing.
 * The default style escapes control characters and null bytes with
 * corresponding C-style control escapes (e.g., `\n`, `\0`), and escapes any
 * backslashes with a second backslash. Any specified flags modify the default
 * style accordingly. If not otherwise noted, any escapings are reversible
 * through `expandUTF8Escapes()`.
 */
enum class UTF8 {
    Default = 0,                    /**< name for unmodified default style */
    EscapeQuotes = (1U << 1U),      /**< escape double quotes with backslashes */
    NoEscapeBackslash = (1U << 2U), /**< do not escape backslashes; this may leave the result non-reversible */
    NoEscapeControl = (1U << 3U),   /**< do not escape control characters and null bytes */
    NoEscapeHex =
        (1U << 4U), /**< do not escape already existing `\xNN` escape codes; this may leave the result non-reversible */
};

} // namespace render_style

} // namespace hilti::rt

enableEnumClassBitmask(hilti::rt::render_style::Bytes); // must be in global scope
enableEnumClassBitmask(hilti::rt::render_style::UTF8);  // must be in global scope

namespace hilti::rt {

/*
 * Escapes non-printable characters in a raw string. This produces a new
 * string that can be reverted by expandEscapes().
 *
 * @param str string to escape
 * @param escape_quotes if true, also escapes quotes characters
 * @param use_octal use `\NNN` instead of `\XX` (needed for C++)
 * @return escaped string
 */
std::string escapeBytes(std::string_view s, bitmask<render_style::Bytes> style = render_style::Bytes::Default);

/*
 * Escapes non-printable and control characters in an UTF8 string. This
 * produces a new string that can be reverted by expandEscapes().
 *
 * @param str string to escape
 * @param escape_quotes if true, also escapes quotes characters
 * @param escape_control if false, do not escape control characters
 * @param keep_hex if true, do not escape our custom "\xYY" escape codes
 * @return escaped std::string
 */
std::string escapeUTF8(std::string_view s, bitmask<render_style::UTF8> style = render_style::UTF8::Default);

/**
 * Joins elements of a range into a string, using a specified delimiter
 * to separate them.
 */
template<std::ranges::input_range T>
std::string join(T&& l, std::string_view delim = "")
    requires(std::is_constructible_v<std::string, std::ranges::range_value_t<T>>)
{
    std::string result;
    bool first = true;

    for ( const auto& i : l ) {
        if ( ! first )
            result.append(delim);

        result.append(i);
        first = false;
    }

    return result;
}

namespace detail {

/** Helper template to detect whether a type is a `Vector`. */
template<typename T>
struct is_Vector : std::false_type {};

template<typename T, typename Allocator>
struct is_Vector<Vector<T, Allocator>> : std::true_type {};

/** Helper which given some container `C` of `X` returns a default constructed
 * container of the same type class as `C` but with element type `Y`. */
template<typename C, typename Y>
constexpr auto transform_result_value(const C&) {
    using X = typename C::value_type;

    if constexpr ( std::is_same_v<C, std::vector<X>> ) {
        return std::vector<Y>();
    }
    else if constexpr ( std::is_same_v<C, std::set<X>> ) {
        return std::set<Y>();
    }
    else if constexpr ( is_Vector<C>::value ) {
        // We do not preserve the allocator since a proper custom one could depend on `Y`.
        return Vector<Y>();
    }
    else if constexpr ( std::is_same_v<C, Set<X>> ) {
        return Set<Y>();
    }
    else
        return std::vector<Y>(); // fallback
}

} // namespace detail

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
inline Iter atoi_n(Iter s, Iter e, uint8_t base, Result* result) {
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

    while ( true ) {
        if ( exp & 1 )
            x *= base;

        exp >>= 1;
        if ( ! exp )
            break;
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

/** Available byte orders. */
HILTI_RT_ENUM(ByteOrder, Little, Big, Network, Host);

/**
 * Returns the byte order of the system we're running on. The result is
 * either `ByteOrder::Little` or `ByteOrder::Big`.
 */
extern ByteOrder systemByteOrder();

namespace detail::adl {
std::string to_string(const ByteOrder& x, tag /*unused*/);
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
 */
std::string strftime(const std::string& format, const Time& time);

/** Parse time from string.
 *
 * This function uses the currently active locale and timezone to parse values.
 *
 * @param buf string to parse
 * @param format format string dictating how to interpret `buf`, see
 *        https://pubs.opengroup.org/onlinepubs/009695399/functions/strptime.html
 *        for the available format specifiers.
 * @return parsed time value
 * @throw `InvalidArgument` if the time value could not be parsed
 *        `OutOfRange` if the parse time value cannot be represented
 */
Time strptime(const std::string& buf, const std::string& format);

// RAII helper to create a temporary directory.
class TemporaryDirectory {
public:
    TemporaryDirectory() {
        const auto tmpdir = hilti::rt::filesystem::temp_directory_path();
        auto template_ = (tmpdir / "hilti-rt-test-XXXXXX").native();
        auto* path = ::mkdtemp(template_.data());
        if ( ! path )
            throw RuntimeError("cannot create temporary directory");

        _path = path;
    }

    TemporaryDirectory(const TemporaryDirectory& other) = delete;
    TemporaryDirectory(TemporaryDirectory&& other) noexcept { _path = std::move(other._path); }

    ~TemporaryDirectory() {
        // In general, ignore errors in this function.
        std::error_code ec;

        if ( ! hilti::rt::filesystem::exists(_path, ec) )
            return;

        // Make sure we have permissions to remove the directory.
        hilti::rt::filesystem::permissions(_path, hilti::rt::filesystem::perms::all, ec);

        // The desugared loop contains an iterator increment which could throw (no automagic call of
        // `std::filesystem::recursive_directory_iterator::increment`), see LWG3013 for the "fix".
        // Ignore errors from that.
        try {
            for ( const auto& entry : hilti::rt::filesystem::recursive_directory_iterator(_path, ec) )
                hilti::rt::filesystem::permissions(entry, hilti::rt::filesystem::perms::all, ec);
        } catch ( ... ) {
            ; // Ignore error.
        }

        hilti::rt::filesystem::remove_all(_path, ec); // ignore errors
    }

    const auto& path() const { return _path; }

    TemporaryDirectory& operator=(const TemporaryDirectory& other) = delete;
    TemporaryDirectory& operator=(TemporaryDirectory&& other) noexcept {
        _path = std::move(other._path);
        return *this;
    }

private:
    hilti::rt::filesystem::path _path;
};

// Combine two or more hashes.
template<typename... Hashes>
constexpr std::size_t hashCombine(std::size_t hash1, std::size_t hash2, Hashes... hashes) {
    auto result = hash1 ^ (hash2 << 1);

    if constexpr ( sizeof...(hashes) > 0 )
        return hashCombine(result, hashes...);
    else
        return result;
}

namespace control {

template<typename Data, typename Error>
class Reference;

/**
 * Helper class for loosely tracking liveliness of some memory.
 *
 * Code using this would instantiate an instance of this pointing to some data.
 * It can then pass out references to that control block by calling `Ref`.
 * One can get values from these references as long as the original control
 * block is live (this is checked).
 *
 * @tparam Data the type of data this Block controls
 * @tparam Error the type of exception a Reference should throw if it became stale
 */
template<typename Data, typename Error>
class Block {
public:
    /**
     * The type of the Reference to this Block.
     */
    using Ref = Reference<Data, Error>;

    Block() = default;
    Block(Data* data) : _data(data) {}

    Block(const Block& other) : Block(other._data) {}
    Block(Block&&) = default;

    Block& operator=(const Block& other) {
        if ( this != &other ) {
            _data = other._data;
            _control.reset();
        }

        return *this;
    }

    Block& operator=(Block&&) = default;

    friend bool operator==(const Block& a, const Block& b) {
        return std::tie(a._control, a._data) == std::tie(b._control, b._data);
    }

    friend bool operator!=(const Block& a, const Block& b) { return ! (a == b); }

    /**
     * Get a Reference to this Block.
     */
    /* implicit */ operator Ref() const {
        if ( ! _control )
            _control = std::make_shared<bool>();

        return {_control, _data};
    }

    /**
     * Invalidate every Reference to this Block.
     */
    void Reset() { _control.reset(); }

private:
    mutable std::shared_ptr<void> _control;
    Data* _data = nullptr;
};

/**
 * A reference to some Block.
 *
 * @tparam Data the type of data this Block controls
 * @tparam Error the type of exception a Reference should throw if it became stale
 */
template<typename Data, typename Error>
class Reference {
public:
    Reference() = default;
    Reference(const Reference&) = default;
    Reference(Reference&&) = default;

    Reference& operator=(const Reference&) = default;
    Reference& operator=(Reference&&) = default;

    /**
     * Check whether getting a value with `get` would return a value.
     */
    bool isValid() const { return _data && ! _control.expired(); }

    /**
     * Get reference to the controlled object.
     *
     * @throws Error if the object has expired or the data is invalid.
     */
    const Data& get() const {
        if ( ! _data )
            throw Error("underlying object is invalid");

        if ( _control.expired() )
            throw Error("underlying object has expired");

        return *_data;
    }

    /**
     * Get reference to the controlled object.
     *
     * @throws Error if the object has expired or the data is invalid.
     */
    Data& get() {
        if ( ! _data )
            throw Error("underlying object is invalid");

        if ( _control.expired() )
            throw Error("underlying object has expired");

        return *_data;
    }

    friend bool operator==(const Reference& a, const Reference& b) {
        return ! a._control.owner_before(b._control) && ! b._control.owner_before(a._control);
    }

    friend bool operator!=(const Reference& a, const Reference& b) { return ! (a == b); }

private:
    template<typename T, typename E>
    friend class Block;

    Reference(std::weak_ptr<void> control, Data* data) : _control(std::move(control)), _data(data) {}

    std::weak_ptr<void> _control;
    Data* _data = nullptr;
};

} // namespace control

/**
 * Clone of `std::experimental::scope_exit` that calls an exit function on destruction.
 */
template<typename EF>
struct scope_exit {
    scope_exit(EF&& f) noexcept : _f(std::forward<EF>(f)) {}

    scope_exit(const scope_exit&) = delete;
    scope_exit(scope_exit&&) = delete;

    ~scope_exit() noexcept {
        try {
            _f();
        } catch ( ... ) {
            // Ignore.
        }
    }

    EF _f;
};

} // namespace hilti::rt
