// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.
//
// Note: We don't run clang-tidy on this file. The use of the JRX's C
// interface triggers all kinds of warnings.

extern "C" {
#include <justrx/jrx.h>
}

#include <hilti/rt/types/regexp.h>
#include <hilti/rt/util.h>

#include <utility>

using namespace hilti::rt;
using namespace hilti::rt::bytes;

// #define _DEBUG_MATCHING

struct regexp::MatchState::Pimpl {
    jrx_accept_id _acc = 0;
    jrx_assertion _first = JRX_ASSERTION_BOL | JRX_ASSERTION_BOD;
    ;
    jrx_match_state _ms{};
    std::shared_ptr<jrx_regex_t> _jrx;
};

regexp::MatchState::MatchState(const RegExp& re) {
    _pimpl = std::make_unique<Pimpl>();
    _pimpl->_jrx = re._jrxShared();
    jrx_match_state_init(_pimpl->_jrx.get(), 0, &_pimpl->_ms);
}

regexp::MatchState::MatchState(const MatchState& other) {
    if ( this == &other )
        return;

    _pimpl = std::make_unique<Pimpl>();
    _pimpl->_acc = other._pimpl->_acc;
    _pimpl->_first = other._pimpl->_first;
    _pimpl->_jrx = other._pimpl->_jrx;
    jrx_match_state_copy(&other._pimpl->_ms, &_pimpl->_ms);
}

regexp::MatchState& regexp::MatchState::operator=(const MatchState& other) {
    if ( this == &other )
        return *this;

    if ( _pimpl )
        jrx_match_state_done(&_pimpl->_ms);

    _pimpl = std::make_unique<Pimpl>();
    _pimpl->_acc = other._pimpl->_acc;
    _pimpl->_first = other._pimpl->_first;
    _pimpl->_jrx = other._pimpl->_jrx;
    jrx_match_state_copy(&other._pimpl->_ms, &_pimpl->_ms);
    return *this;
}

regexp::MatchState::MatchState() noexcept = default;
regexp::MatchState& regexp::MatchState::operator=(MatchState&&) noexcept = default;
regexp::MatchState::MatchState(MatchState&&) noexcept = default;

regexp::MatchState::~MatchState() {
    if ( _pimpl )
        jrx_match_state_done(&_pimpl->_ms);
}

std::tuple<int32_t, stream::View> regexp::MatchState::advance(const stream::View& data) {
    if ( ! _pimpl )
        throw PatternError("no regular expression associated with match state");

    if ( ! _pimpl->_jrx )
        throw MatchStateReuse("matching already complete");

    auto [rc, offset] = _advance(data, data.isFrozen());

    if ( rc >= 0 ) {
        _pimpl->_jrx = nullptr;
        return std::make_tuple(rc, data.trim(data.safeBegin() + offset));
    }

    return std::make_tuple(rc, data.trim(data.safeBegin() + data.size()));
}

std::tuple<int32_t, uint64_t> regexp::MatchState::advance(const Bytes& data, bool is_final) {
    if ( ! _pimpl )
        throw PatternError("no regular expression associated with match state");

    if ( ! _pimpl->_jrx )
        throw MatchStateReuse("matching already complete");

    auto [rc, offset] = _advance(Stream(data).view(), is_final);

    if ( rc >= 0 ) {
        _pimpl->_jrx = nullptr;
        return std::make_tuple(rc, offset);
    }

    return std::make_tuple(rc, data.size());
}

std::pair<int32_t, uint64_t> regexp::MatchState::_advance(const stream::View& data, bool is_final) {
    jrx_assertion first = _pimpl->_first;
    jrx_assertion last = 0;

    if ( data.size() )
        _pimpl->_first = 0;

    _pimpl->_ms.offset = 1; // See below why 1.

    if ( data.isEmpty() ) {
        if ( is_final && _pimpl->_acc <= 0 )
            _pimpl->_acc = jrx_current_accept(&_pimpl->_ms);

        return std::make_pair(is_final ? _pimpl->_acc : -1, 0);
    }

    stream::detail::UnsafeConstIterator cur(data.safeBegin());
    cur += 0; // this will normalize the internal chunk
    jrx_accept_id rc = 0;

    unsigned consumed = 0; // Counter for the size of the consumed data.

    // We iterate over raw arrays of continous memory underlying the
    // stream data, using the internal API.
    for ( auto chunk = cur.chunk(); chunk; chunk = chunk->next().get() ) {
        if ( is_final && chunk->isLast() )
            last |= (JRX_ASSERTION_EOL | JRX_ASSERTION_EOD);

        auto block_start = (chunk == cur.chunk() ? chunk->data(data.safeBegin().offset()) : chunk->begin());
        auto block_len = (chunk->end() - block_start);

        // Since chunks are raw pointers with no knowledge of the size of the
        // passed data, make sure we do not consume more data than is in the
        // input after creating the chunk.
        consumed += block_len;
        if ( consumed > data.size() ) {
            is_final = true;
            block_len -= consumed - data.size();
        }

#ifdef _DEBUG_MATCHING
        std::cerr << fmt("feeding |%s| data.offset=%lu\n",
                         escapeBytes(std::string_view((const char*)block_start, block_len)), data.safeBegin().offset());
#endif

        rc = jrx_regexec_partial(_pimpl->_jrx.get(), reinterpret_cast<const char*>(block_start), block_len, first, last,
                                 &_pimpl->_ms, is_final);

        // FIXME: The jrx match_state intializes the offset with 1. Not sure
        // why right now but changing that would probably break other things
        // we adjust that here for the calculation.
        uint64_t view_offset = chunk->offset() + _pimpl->_ms.offset - 1 - cur.chunk()->offset();

#ifdef _DEBUG_MATCHING
        std::cerr << fmt("-> state=%p rc=%d ms->offset=%d\n", this, rc, _pimpl->_ms.offset);
#endif

        if ( rc == 0 )
            // No further match possible.
            return std::make_pair(_pimpl->_acc > 0 ? _pimpl->_acc : 0, view_offset);

        if ( rc > 0 ) {
            // Match found. However, we need to wait for more data that could
            // potentially be included into the match before returning it.
            if ( ! is_final && jrx_can_transition(&_pimpl->_ms) )
                return std::make_pair(-1, 0);

            _pimpl->_acc = rc;
            return std::make_pair(_pimpl->_acc, view_offset);
        }
    };

    if ( rc < 0 && _pimpl->_acc == 0 )
        // At least one could match with more data.
        _pimpl->_acc = -1;

    return std::make_pair(_pimpl->_acc, 0);
}

RegExp::RegExp(std::string pattern, regexp::Flags flags) : _flags(flags) {
    _newJrx();
    _compileOne(std::move(pattern), 0);
    jrx_regset_finalize(_jrx());
}


RegExp::RegExp(const std::vector<std::string>& patterns, regexp::Flags flags) : _flags(flags) {
    if ( patterns.empty() )
        throw regexp::PatternError("trying to compile empty pattern set");

    _flags.no_sub = true;
    _newJrx();

    int idx = 0;
    for ( const auto& p : patterns )
        _compileOne(p, idx++);

    jrx_regset_finalize(_jrx());
}

void RegExp::_newJrx() {
    if ( _jrx_shared )
        throw regexp::PatternError("regexp already compiled");

    int cflags = (REG_EXTENDED | REG_LAZY); // | REG_DEBUG;

    if ( _flags.no_sub )
        cflags |= (REG_NOSUB | REG_ANCHOR);

    _patterns.clear();
    _jrx_shared = std::shared_ptr<jrx_regex_t>(new jrx_regex_t, [=](auto j) {
        jrx_regfree(j);
        delete j;
    });
    jrx_regset_init(_jrx(), -1, cflags);
}

void RegExp::_compileOne(std::string pattern, int idx) {
    if ( auto rc = jrx_regset_add(_jrx(), pattern.c_str(), pattern.size()); rc != REG_OK ) {
        static char err[256];
        jrx_regerror(rc, _jrx(), err, sizeof(err));
        throw regexp::PatternError(fmt("error compiling pattern '%s': %s", pattern, err));
    }

    _patterns.push_back(std::move(pattern));
}

int32_t RegExp::find(const Bytes& data) const {
    if ( ! _jrx() )
        throw regexp::PatternError("regexp not compiled");

    jrx_match_state ms;
    jrx_accept_id acc = _search_pattern(&ms, data, nullptr, nullptr, false, true);
    jrx_match_state_done(&ms);
    return acc;
}

static Bytes _subslice(const Bytes& data, jrx_offset so, jrx_offset eo) {
    return Bytes(data.sub(data.begin() + so, data.begin() + eo));
}

std::tuple<int32_t, Bytes> RegExp::findSpan(const Bytes& data) const {
    if ( ! _jrx() )
        throw regexp::PatternError("regexp not compiled");

    jrx_offset so = -1;
    jrx_offset eo = -1;
    jrx_match_state ms;
    auto rc = _search_pattern(&ms, data, &so, &eo, false, true);
    jrx_match_state_done(&ms);

    if ( rc > 0 )
        return std::make_tuple(rc, _subslice(data, so, eo));


    return std::make_tuple(rc, ""_b);
}

Vector<Bytes> RegExp::findGroups(const Bytes& data) const {
    if ( ! _jrx() )
        throw regexp::PatternError("regexp not compiled");

    if ( _patterns.size() > 1 )
        throw regexp::NotSupported("cannot capture groups during set matching");

    jrx_offset so = -1;
    jrx_offset eo = -1;
    jrx_match_state ms;
    auto rc = _search_pattern(&ms, data, &so, &eo, false, true);

    Vector<Bytes> groups;

    if ( rc > 0 ) {
        groups.emplace_back(_subslice(data, so, eo));

        if ( auto num_groups = jrx_num_groups(_jrx()); num_groups > 1 ) {
            jrx_regmatch_t pmatch[num_groups];
            jrx_reggroups(_jrx(), &ms, num_groups, pmatch);

            for ( int i = 1; i < num_groups; i++ ) {
                if ( pmatch[i].rm_so >= 0 )
                    groups.emplace_back(_subslice(data, pmatch[i].rm_so, pmatch[i].rm_eo));
            }
        }
    }

    jrx_match_state_done(&ms);
    return groups;
}

regexp::MatchState RegExp::tokenMatcher() const { return regexp::MatchState(*this); }

// TODO: This is stripped down version of the previous view-based matchig
// code (see below for original code). Not sure if we still need all of this,
// or could just call jrx-* functions directly instead of _search_pattern.
jrx_accept_id RegExp::_search_pattern(jrx_match_state* ms, const Bytes& data, jrx_offset* so, jrx_offset* eo,
                                      bool do_anchor, bool find_partial_matches) const {
    assert((! do_anchor) || _flags.no_sub);
    const auto use_stdmatcher = ! _flags.no_sub;
    const jrx_assertion last = JRX_ASSERTION_EOL | JRX_ASSERTION_EOD;
    jrx_assertion first = JRX_ASSERTION_BOL | JRX_ASSERTION_BOD;

    jrx_accept_id acc = 0;
    int8_t need_msdone = 0;

    if ( data.isEmpty() ) {
        // Nothing to do, but still need to init the match state.
        jrx_match_state_init(_jrx(), 0, ms);
        return -1;
    }

    jrx_offset cur = 0;

    while ( acc <= 0 && cur < data.size() ) {
        if ( need_msdone ) {
            jrx_match_state_done(ms);

            if ( jrx_is_anchored(_jrx()) )
                return 0;

            first = 0;
        }

        need_msdone = 1;

        jrx_match_state_init(_jrx(), cur, ms);

        auto block_start = data.data() + cur;
        auto block_len = data.size() - cur;

#ifdef _DEBUG_MATCHING
        std::cerr << fmt("feeding |%s| use_stdmatcher=%u do_anchor=%u first=%u last=%u\n",
                         escapeBytes(std::string_view((const char*)block_start, block_len)), use_stdmatcher, do_anchor,
                         first, last);
#endif
        auto rc = jrx_regexec_partial(_jrx(), reinterpret_cast<const char*>(block_start), block_len, first, last, ms,
                                      find_partial_matches);

#ifdef _DEBUG_MATCHING
        std::cerr << fmt("-> rc=%d ms->offset=%d\n", rc, ms->offset);
#endif
        if ( use_stdmatcher && rc == 0 )
            // No further match.
            return acc;

        if ( rc > 0 ) {
            // Match.
            acc = rc;
#ifdef _DEBUG_MATCHING
            std::cerr << fmt("offset=%ld ms->offset=%d eo=%p so=%p\n", cur, ms->offset - 1, eo, so);
#endif

            if ( ! use_stdmatcher ) {
                if ( so )
                    *so = cur;

                if ( eo )
                    // FIXME: The match_state intializes the offset with
                    // 1. Not sure why right now but changing that would
                    // probably break other things we adjust that here
                    // for the calculation.
                    *eo = cur + ms->offset - 1;
            }
            else if ( so || eo ) {
                jrx_regmatch_t pmatch;
                jrx_reggroups(_jrx(), ms, 1, &pmatch);

                if ( so )
                    *so = pmatch.rm_so;

                if ( eo )
                    *eo = pmatch.rm_eo;
            }

            return acc;
        }

        if ( rc < 0 && acc == 0 )
            // At least one could match with more data.
            acc = -1;

        if ( use_stdmatcher || do_anchor )
            // We compiled with an implicit ".*", or are asked to anchor.
            break;

        ++cur;
    }

    if ( ! use_stdmatcher && acc == 0 )
        // Adding more data may always help.
        return -1;

    return acc;
}

#if 0
// Searches for the regexp anywhere inside a bytes view and returns the first
// match.
//
// Note: This is the streaming version which we don't need for bytes anymore,
// but could bring back for streans.

/*
jrx_accept_id RegExp::_search_pattern(jrx_match_state* ms, const bytes::View& data, jrx_offset* so, jrx_offset* eo,
                                      bool do_anchor, bool find_partial_matches) const {
    // We follow one of two strategies here:
    //
    // (1) If the compilation was compiled with the ability to capture
    // subgroups, we have to use the more expensive standard matcher anyway.
    // In that case, the compilation didn't anchor the regexp (i.e,, it will
    // start with an implicit ".*") and we just need a single matching
    // process over all the data.
    //
    // (2) If we compiled with REG_NOSUB, we iterate ourselves over all
    // possible starting positions so that even though using the more
    // efficinet minimal matcher, we can still get starting and end
    // positions. (Setting do_anchor to 1 prevents the iteration and will
    // only match right from the beginning. Note that this flag only works
    // with REG_NOSUB).
    //
    // If find_partial_matches is 0, we don't report a match as long as more
    // input could still change the result (i.e., there are still DFA
    // transitions possible after processing the last bytes). In this case,
    // the function returns -1 as if there wasn't any match yet.
    //
    // FIXME: In (2), we might be doing a bit more comparisions than with an
    // implicit .*, and the manual loop also adds a bit overhead. That seems
    // worth it but should reevaluate the trade-off later.

    jrx_assertion first = JRX_ASSERTION_BOL | JRX_ASSERTION_BOD;
    jrx_assertion last = 0;
    jrx_accept_id acc = 0;
    int8_t need_msdone = 0;
    bytes::Offset offset = 0;
    int bytes_seen = 0;

    assert( (! do_anchor) || _flags.no_sub );
    const auto use_stdmatcher = ! _flags.no_sub;

    if ( data.isEmpty() ) {
        // Nothing to do, but still need to init the match state.
        jrx_match_state_init(_jrx(), offset, ms);
        return -1;
    }

    Iterator cur(data.safeBegin());

    while ( acc <= 0 && cur != data.safeEnd() ) {
        if ( need_msdone )
            jrx_match_state_done(ms);

        need_msdone = 1;
        bytes_seen = 0;

        jrx_match_state_init(_jrx(), offset, ms);

        // We iterate over raw arrays of continous memory underlying the
        // bytes data, using the internal API.
        for ( auto chunk = cur.chunk(); chunk; chunk = chunk->next().get() ) {
            if ( chunk->isLast() )
                last |= JRX_ASSERTION_EOL | JRX_ASSERTION_EOD;

            auto block_start = chunk->data(cur.offset());
            auto block_end = chunk->end();
            auto block_len = (block_end - block_start);
            auto fpm = chunk->isLast() && find_partial_matches;

#ifdef _DEBUG_MATCHING
            std::cerr << fmt("feeding |%s| use_stdmatcher=%u do_anchor=%u first=%u last=%u\n",
                             escapeBytes(std::string_view((const char*)block_start, block_len)), use_stdmatcher,
                             do_anchor, first, last);
#endif
            auto rc = jrx_regexec_partial(_jrx(), reinterpret_cast<const char*>(block_start), block_len, first, last,
                                          ms, fpm);

#ifdef _DEBUG_MATCHING
            std::cerr << fmt("-> rc=%d ms->offset=%d\n", rc, ms->offset);
#endif
            if ( use_stdmatcher && rc == 0 )
                // No further match.
                return acc;

            if ( rc > 0 ) {
                // Match.
                acc = rc;
#ifdef _DEBUG_MATCHING
                std::cerr << fmt("offset=%ld ms->offset=%d bytes_seen=%d eo=%p so=%p\n", offset, ms->offset - 1,
                                 bytes_seen, eo, so);
#endif

                if ( ! use_stdmatcher ) {
                    if ( so )
                        *so = offset;

                    if ( eo )
                        // FIXME: The match_state intializes the offset with
                        // 1. Not sure why right now but changing that would
                        // probably break other things we adjust that here
                        // for the calculation.
                        *eo = offset + ms->offset - 1;
                }
                else if ( so || eo ) {
                    jrx_regmatch_t pmatch;
                    jrx_reggroups(_jrx(), ms, 1, &pmatch);

                    if ( so )
                        *so = pmatch.rm_so;

                    if ( eo )
                        *eo = pmatch.rm_eo;
                }

                return acc;
            }

            bytes_seen += block_len;

            if ( chunk->isLast() && rc < 0 && acc == 0 )
                // At least one could match with more data.
                acc = -1;
        }

        if ( use_stdmatcher || do_anchor )
            // We compiled with an implicit ".*", or are asked to anchor.
            break;

        ++cur;
        ++offset;
        first = 0;
    }

    if ( ! use_stdmatcher && acc == 0 )
        // Adding more data may always help.
        return -1;

    return acc;
}
*/
#endif

std::string hilti::rt::detail::adl::to_string(const RegExp& x, adl::tag /*unused*/) {
    if ( x.patterns().empty() )
        return "<regexp wo/ pattern>";

    auto p = join(transform(x.patterns(), [&](auto s) { return fmt("/%s/", s); }), " | ");

    auto f = std::vector<std::string>();

    if ( x.flags().no_sub )
        f.emplace_back("&nosub");

    if ( f.empty() )
        return p;

    return fmt("%s %s", p, join(f, " "));
}
