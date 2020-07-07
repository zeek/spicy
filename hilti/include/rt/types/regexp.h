// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

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

/** Exception indicating trouble when compiling a regular expression. */
HILTI_EXCEPTION(PatternError, RuntimeError)

/** Exception indicating use of unsupport matching capabilities. */
HILTI_EXCEPTION(NotSupported, RuntimeError)

/** Exception indicating illegal reuse of MatchState. **/
HILTI_EXCEPTION(MatchStateReuse, RuntimeError)

struct Flags {
    bool no_sub : 1; /**< Compile without support for capturing sub-expressions. */
};

/**
 * Match state for incremental regexp matching. This is tailored for token
 * matching: it's anchored and does not support capture groups.
 *
 * @note We don't make this part of the public API to avoid dependending on
 * the jrx header.
 **/
class MatchState {
public:
    /**
     * Creates a fresh instances ready to match data against a given regular expression.
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
     * will be assumd to be the last chunk of data, and
     * the result of any further calls to `advance()` will then trigger a
     * `MatchStateReuse` exception
     *
     * @returns A tuple in which the integer is: (1) larger than zero if a
     * match has been found; for sets compiled via `compileSet` the integer
     * value then indicates the ID of the pattern that was found. (2) zero if
     * no match was found and advancing further to more data is guaranteed to
     * not change that fact. (3) smaller than 0 if no match was found so far
     * but advancing further may change that. In either case, the returned
     * view trims *data* to the part not consumed yet.
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
     * *data* by the matching.
     */
    std::tuple<int32_t, uint64_t> advance(const Bytes& data, bool is_final = false);

private:
    std::pair<int32_t, uint64_t> _advance(const stream::View& data, bool is_final);

    // TODO(robin): PIMPLing here means we have to alllocate dynamic memory, which
    // isn't great for this class. However, without PIMPL we get a new dependency on
    // 'jrx.h', which isn't great either. Better ideas?
    class Pimpl;
    std::unique_ptr<Pimpl> _pimpl;
};

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

    RegExp() = default;

    const auto& patterns() const { return _patterns; }
    const auto& flags() const { return _flags; }

    /**
     * Searches a pattern within a bytes view.
     *
     * @return If the returned integer is larger than zero, the regexp was
     * found; for sets compiled via `compileSet` the integer value then
     * indicates the ID of the pattern that was found. If the function
     * returns zero, no match was found and that won't change if further
     * data gets added to the input data. If the returned value is smaller than
     * 0, a partial match was found (i.e., no match yet but adding further
     * data could change that).
     */
    int32_t find(const Bytes& data) const;

    /**
     * Searches a pattern within a bytes view and returns the matching part.
     *
     * @return A tuple where the 1st element corresponds to the result of
     * `find()`. If that's larger than zero, the 2nd is the matching data.
     */
    std::tuple<int32_t, Bytes> findSpan(const Bytes& data) const;

    /**
     * Searches a pattern within a bytes view and returns the matching data
     * for all matching capture groups.
     *
     * @return A vector of containing the matching data for all capture
     * groups. The vector's index 0 corresponds to the whole expression,
     * index 1 to the first capture group etc. If no match is found, the
     * returned vector is empty.
     *
     * @todo This function does not yet support sets compiled via
     * `compileSet()`.
     */
    Vector<Bytes> findGroups(const Bytes& data) const;

    /**
     * Returns matching state initializes for incremental token matching. For
     * token matching the regular expression will be considered implicitly
     * anchored. The regular expression must have been compiled with the
     * `&nosub` attribute.
     */
    regexp::MatchState tokenMatcher() const;

private:
    friend class regexp::MatchState;

    jrx_regex_t* _jrx() const {
        assert(_jrx_shared && "regexp not compiled");
        return _jrx_shared.get();
    }
    const auto& _jrxShared() const { return _jrx_shared; }

    /**
     * Searches for the regexp anywhere inside a bytes instance and returns
     * the first match.
     */
    int16_t _search_pattern(jrx_match_state* ms, const Bytes& data, int32_t* so, int32_t* eo, bool do_anchor,
                            bool find_partial_matches) const;

    void _newJrx();
    void _compileOne(std::string pattern, int idx);

    regexp::Flags _flags{};
    std::vector<std::string> _patterns;
    std::shared_ptr<jrx_regex_t>
        _jrx_shared; // Shared ptr so that we can copy by value, and safely share with match state.
};

namespace detail::adl {
extern std::string to_string(const RegExp& x, adl::tag /*unused*/);

inline std::string to_string(const regexp::MatchState& /*unused*/, adl::tag /*unused*/) {
    return "<regexp-match-state>";
}

} // namespace detail::adl

} // namespace hilti::rt
