// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <optional>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include <hilti/rt/extension-points.h>
#include <hilti/rt/types/bytes.h>
#include <hilti/rt/types/stream.h>
#include <hilti/rt/types/vector.h>

extern "C" {
struct jrx_regex_t;
struct jrx_match_state;
}

namespace hilti::rt {

class RegExp;

namespace regexp {

struct Flags {
    bool no_sub = false; /**< if true, compile without support for capturing sub-expressions */
    bool use_std =
        false; /**< if true, always use the standard matcher (for testing purposes; ignored if `no_sub` is set) */

    /** Returns a string uniquely identifying the set of flags. */
    std::string cacheKey() const {
        char key[2] = {no_sub ? '1' : '0', use_std ? '1' : '0'};
        return std::string(key, 2);
    }
};

/* Type for passing around the content of extracted capture groups. */
using Captures = Vector<Bytes>;

/** Match state for incremental regexp matching. **/
class MatchState {
public:
    /**
     * Creates a fresh instances ready to match data against a given regular
     * expression. The expression will considered anchored to the beginning of
     * any data.
     */
    MatchState(const RegExp& re);
    MatchState() noexcept;
    ~MatchState();
    MatchState(const MatchState& other);
    MatchState(MatchState&& /*unused*/) noexcept;
    MatchState& operator=(const MatchState& other);
    MatchState& operator=(MatchState&& /*unused*/) noexcept;

    /**
     * Feeds the next chunk of data into the matcher.
     *
     * @param data chunk of data; if the underlying stream is frozen, this
     * will be assumed to be the last chunk of data, and
     * the result of any further calls to `advance()` will then trigger a
     * `MatchStateReuse` exception
     *
     * @returns A tuple in which the integer is: (1) larger than zero if a
     * match has been found; for sets compiled via `compileSet` the integer
     * value then indicates the ID of the pattern that was found. (2) zero if
     * no match was found and advancing further to more data is guaranteed to
     * not change that fact. (3) smaller than 0 if no match was found so far
     * but advancing further may change that. In either case, the returned view
     * trims *data* to the part not consumed yet. Note that the latter could
     * actually be *more* than what was previously returned in case matching
     * needed to backtrack because of a match now determined to end earlier.
     */
    std::tuple<int32_t, stream::View> advance(const stream::View& data);

    /**
     * Feeds the next chunk of data into the matcher.
     *
     * @param data chunk of data
     *
     * @param is_final true to signal the last chunk of data; the result of
     * any further calls to `advance()` will then trigger a `MatchStateReuse`
     * exception

     * @returns A tuple in which the integer is: (1) larger than zero if a
     * match has been found; for sets compiled via `compileSet` the integer
     * value then indicates the ID of the pattern that was found. (2) zero if
     * no match was found and advancing further to more data is guaranteed to
     * not change that fact. (3) smaller than 0 if no match was found so far
     * but advancing further may change that. In either case, the 2nd element
     * in the tuple returns the number of bytes that were consumed from
     * *data* by the matching. Note that the integer can be *negative* in case
     * of a match that has now been determined to end before the current chunk.
     * In that case, the caller needs to backtrack by the given number of
     * bytes. Because this could be tricky to handle, it's usually better to
     * use the other variant of `advance()`, returning a view, if possible.
     */
    std::tuple<int32_t, int64_t> advance(const Bytes& data, bool is_final = false);

    /**
     * Returns extracted capture groups after successful matching.
     * Element zero will contain the full match. For i>0, index i will
     * contain the i'th capture group. If capture groups cannot be
     * extracted (e.g., because the regexp was compiled without
     * support for that, or when matching has not finished
     * successfully), the return vector will be empty.
     */
    Captures captures(const Stream& data) const;

private:
    // Returns (rc, bytes-consumed). Note that the latter can be negative if
    // backtracking is required.
    std::pair<int32_t, int64_t> _advance(const stream::View& data, bool is_final);

    // PIMPLing here means we have to allocate dynamic memory, which
    // isn't great for this class. However, without PIMPL we get a new dependency on
    // 'jrx.h', which isn't great either, so we go with this.
    class Pimpl;
    std::unique_ptr<Pimpl> _pimpl;
};

namespace detail {

// Internal helper class to compile and cache regular expressions. We compile
// each unique set of patterns once into an instance of this class, which we
// then retain inside a global cache for later reuse when seeing the same set
// of patterns again.
class CompiledRegExp {
public:
    CompiledRegExp(const std::vector<std::string>& patterns, regexp::Flags flags);
    ~CompiledRegExp() = default;

    CompiledRegExp(const CompiledRegExp& other) = delete;
    CompiledRegExp(CompiledRegExp&& other) = delete;
    CompiledRegExp& operator=(const CompiledRegExp& other) = delete;
    CompiledRegExp& operator=(CompiledRegExp&& other) = delete;

    jrx_regex_t* jrx() const {
        assert(_jrx && "regexp not compiled");
        return _jrx.get();
    }

private:
    friend class rt::RegExp;
    friend class regexp::MatchState;

    struct RegFree {
        void operator()(jrx_regex_t* j);
    };

    void _newJrx();
    void _compileOne(std::string pattern, int idx);

    regexp::Flags _flags{};
    std::vector<std::string> _patterns;
    std::unique_ptr<jrx_regex_t, RegFree> _jrx;
};

} // namespace detail
} // namespace regexp

/** A regular expression instance. */
class RegExp {
public:
    /**
     * Instantiates a new regular expression instance.
     *
     * @param pattern regular expression to compile
     * @param flags compilation flags for the regexp
     * @exception `PatternError` if the pattern cannot be compiled
     */
    RegExp(std::string pattern, regexp::Flags flags = regexp::Flags());

    /**
     * Instantiates a new regular expression instance performing parallel set
     * matching on multiple patterns. Set matching implicitly sets the
     * `Flags::no_sub` (even if just one pattern is passed in).
     *
     * @param patterns regular expressions to compile jointly
     * @param flags compilation flags for the regexp
     * @exception `PatternError` if a pattern cannot be compiled
     */
    RegExp(const std::vector<std::string>& patterns, regexp::Flags flags = regexp::Flags());

    /**
     * Instantiates an empty regular expression without any patterns. This is
     * a valid instance that however cannot be used with any matching
     * functionality. Doing will produce runtime errors.
     */
    RegExp();

    const auto& patterns() const { return _re->_patterns; }
    const auto& flags() const { return _re->_flags; }

    /**
     * Searches a pattern within a bytes view. The expression is considered
     * anchored to the beginning of the data.
     *
     * @return If the returned integer is larger than zero, the regexp was
     * found; for sets compiled via `compileSet` the integer value then
     * indicates the ID of the pattern that was found. If the function
     * returns zero, no match was found and that won't change if further
     * data gets added to the input data. If the returned value is smaller than
     * 0, a partial match was found (i.e., no match yet but adding further
     * data could change that).
     */
    int32_t match(const Bytes& data) const;

    /**
     * Searches a pattern within a bytes view and returns the matching data for
     * all matching capture groups. The expression is considered anchored to
     * the beginning of the data.
     *
     * @return A vector of containing the matching data for all capture
     * groups. The vector's index 0 corresponds to the whole expression,
     * index 1 to the first capture group etc. If no match is found, the
     * returned vector is empty.
     *
     * @todo This function does not yet support sets compiled via
     * `compileSet()`.
     */
    Vector<Bytes> matchGroups(const Bytes& data) const;

    /**
     * Searches a pattern within a bytes view and returns the matching part.
     * The expression is *not* considered anchored to the beginning of the data,
     * it will be found at any position.
     *
     * \note This method is currently quadratic in the size of *data*.
     *
     * @return A tuple where the 1st element corresponds to the result of
     * `find()`. If that's larger than zero, the 2nd is the matching data.
     */
    std::tuple<int32_t, Bytes> find(const Bytes& data) const;

    /**
     * Returns matching state initializes for incremental token matching. For
     * token matching the regular expression will be considered implicitly
     * anchored.
     */
    regexp::MatchState tokenMatcher() const;

    /** Accessor to underlying JRX state. Intended for internal use and testing. */
    jrx_regex_t* jrx() const { return _re->jrx(); }

    bool operator==(const RegExp& other) const {
        // Due to caching uniqueing instances, we can just compare the pointers.
        return _re == other._re;
    }

private:
    friend class regexp::MatchState;

    // Backend for the searching and matching methods.
    int16_t _search_pattern(jrx_match_state* ms, const char* data, size_t len, int32_t* so, int32_t* eo) const;

    std::shared_ptr<regexp::detail::CompiledRegExp> _re;
};

namespace detail::adl {
extern std::string to_string(const RegExp& x, adl::tag /*unused*/);

inline std::string to_string(const regexp::MatchState& /*unused*/, adl::tag /*unused*/) {
    return "<regexp-match-state>";
}

} // namespace detail::adl

inline std::ostream& operator<<(std::ostream& out, const RegExp& x) {
    out << to_string(x);
    return out;
}

} // namespace hilti::rt
