// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.
//
// Note: We don't run clang-tidy on this file. The use of the JRX's C
// interface triggers all kinds of warnings.

#include <utility>

#include <hilti/rt/global-state.h>
#include <hilti/rt/types/regexp.h>
#include <hilti/rt/util.h>

extern "C" {
#include <justrx/jrx.h>
}

using namespace hilti::rt;
using namespace hilti::rt::bytes;

// #define _DEBUG_MATCHING

// Determines which matcher (std vs. min) to use.
static bool _use_std_matcher(jrx_regex_t* jrx, jrx_match_state* ms) {
    // Order of the checks is important.
    bool std = true;

    if ( jrx_num_groups(jrx) == 1 )
        // No captures groups used, so don't need the standard matcher.
        std = false;

    if ( ms->cflags & REG_STD_MATCHER )
        // Forced to use the standard matcher.
        std = true;

    if ( ms->cflags & REG_NOSUB )
        // Explicitly asked to not capture.
        std = false;

    return std;
}

class regexp::MatchState::Pimpl {
public:
    jrx_accept_id _acc = 0;
    jrx_assertion _first = JRX_ASSERTION_BOL | JRX_ASSERTION_BOD;
    bool _done = false;

    jrx_match_state _ms{};
    std::shared_ptr<regexp::detail::CompiledRegExp> _re;

    ~Pimpl() { jrx_match_state_done(&_ms); }

    Pimpl(std::shared_ptr<regexp::detail::CompiledRegExp> re) : _re(std::move(re)) {
        jrx_match_state_init(_re->jrx(), 0, &_ms);
    }

    Pimpl(const Pimpl& other) : _acc(other._acc), _first(other._first), _re(other._re) {
        jrx_match_state_copy(&other._ms, &_ms);
    }
};

regexp::MatchState::MatchState(const RegExp& re) {
    if ( re.patterns().empty() )
        throw PatternError("trying to match empty pattern set");

    _pimpl = std::make_unique<Pimpl>(re._re);
}

regexp::MatchState::MatchState(const MatchState& other) {
    if ( this == &other )
        return;

    if ( other._pimpl->_re->jrx()->cflags & REG_STD_MATCHER )
        throw InvalidArgument("cannot copy match state of regexp with sub-expressions support");

    _pimpl = std::make_unique<Pimpl>(*other._pimpl);
}

regexp::MatchState& regexp::MatchState::operator=(const MatchState& other) {
    if ( this == &other )
        return *this;

    if ( other._pimpl->_re->jrx()->cflags & REG_STD_MATCHER )
        throw InvalidArgument("cannot copy match state of regexp with sub-expressions support");

    _pimpl = std::make_unique<Pimpl>(*other._pimpl);

    return *this;
}

regexp::MatchState::MatchState() noexcept = default;
regexp::MatchState& regexp::MatchState::operator=(MatchState&&) noexcept = default;
regexp::MatchState::MatchState(MatchState&&) noexcept = default;

regexp::MatchState::~MatchState() = default;

Tuple<integer::safe<int32_t>, stream::View> regexp::MatchState::advance(const stream::View& data) {
    if ( ! _pimpl )
        throw PatternError("no regular expression associated with match state");

    if ( _pimpl->_done )
        throw MatchStateReuse("matching already complete");

    auto [rc, offset] = _advance(data, data.isComplete());

    stream::View ndata;
    // `SafeConstIterator` implements both `operator+` and `operator-` for `uint64_t`
    // while `offset` is a `int64_t`. Make sure we trim in the correct direction.
    if ( offset >= 0 )
        ndata = data.trim(data.begin() + offset);
    else
        ndata = data.trim(data.begin() - static_cast<uint64_t>((-offset)));

    if ( rc >= 0 ) {
        _pimpl->_done = true;
        return tuple::make(integer::safe<int32_t>{rc}, std::move(ndata));
    }

    return tuple::make<integer::safe<int32_t>, stream::View>(rc, std::move(ndata));
}

Tuple<int32_t, int64_t> regexp::MatchState::advance(const Bytes& data, bool is_final) {
    if ( ! _pimpl )
        throw PatternError("no regular expression associated with match state");

    if ( _pimpl->_done )
        throw MatchStateReuse("matching already complete");

    auto [rc, offset] = _advance(Stream(data).view(), is_final);

    if ( rc >= 0 ) {
        _pimpl->_done = true;
        return tuple::make(rc, offset);
    }

    return tuple::make(rc, offset);
}

std::pair<int32_t, int64_t> regexp::MatchState::_advance(const stream::View& data, bool is_final) {
    jrx_assertion first = _pimpl->_first;
    jrx_assertion last = 0;

    if ( data.size() )
        _pimpl->_first = 0;

    if ( data.isEmpty() ) {
        if ( is_final && _pimpl->_acc <= 0 )
            _pimpl->_acc = static_cast<jrx_accept_id>(jrx_current_accept(&_pimpl->_ms));

        return std::make_pair(is_final ? _pimpl->_acc : -1, 0);
    }

    jrx_accept_id rc = 0;
    auto use_std_matcher = _use_std_matcher(_pimpl->_re->jrx(), &_pimpl->_ms);
    auto start_ms_offset = _pimpl->_ms.offset;

    for ( auto block = data.firstBlock(); block; block = data.nextBlock(block) ) {
        const auto final_block = is_final && block->is_last;
        if ( final_block )
            last |= (JRX_ASSERTION_EOL | JRX_ASSERTION_EOD);

#ifdef _DEBUG_MATCHING
        std::cerr << fmt("feeding |%s| data.offset=%lu use_std_matcher=%u\n",
                         escapeBytes(std::string_view((const char*)block->start, block->size)), data.begin().offset(),
                         use_std_matcher);
#endif

        if ( use_std_matcher )
            rc = static_cast<jrx_accept_id>(
                jrx_regexec_partial_std(_pimpl->_re->jrx(), reinterpret_cast<const char*>(block->start), block->size,
                                        first, last, &_pimpl->_ms, final_block));
        else
            rc = static_cast<jrx_accept_id>(
                jrx_regexec_partial_min(_pimpl->_re->jrx(), reinterpret_cast<const char*>(block->start), block->size,
                                        first, last, &_pimpl->_ms, final_block));

        // Note: The JRX match_state initializes offsets with 1.

#ifdef _DEBUG_MATCHING
        std::cerr << fmt("-> state=%p rc=%d ms->offset=%d\n", this, rc, _pimpl->_ms.offset);
#endif

        if ( rc == 0 )
            // No further match possible.
            return std::make_pair(_pimpl->_acc > 0 ? _pimpl->_acc : 0, _pimpl->_ms.offset - start_ms_offset);

        if ( rc > 0 ) {
            _pimpl->_acc = rc;
            return std::make_pair(_pimpl->_acc, _pimpl->_ms.match_eo - start_ms_offset);
        }
    }

    if ( rc < 0 && _pimpl->_acc == 0 )
        // At least one could match with more data.
        _pimpl->_acc = -1;

    if ( rc > 0 )
        return std::make_pair(_pimpl->_acc, _pimpl->_ms.match_eo - start_ms_offset);

    return std::make_pair(_pimpl->_acc, _pimpl->_ms.offset - start_ms_offset);
}

regexp::Captures regexp::MatchState::captures(const stream::View& data) const {
    if ( _pimpl->_re->_flags.no_sub || _pimpl->_acc <= 0 || ! _pimpl->_done )
        return Captures();

    Captures captures = {};

    auto num_groups = jrx_num_groups(_pimpl->_re->jrx());
    std::vector<jrx_regmatch_t> groups(num_groups);
    if ( jrx_reggroups(_pimpl->_re->jrx(), &_pimpl->_ms, num_groups, groups.data()) == REG_OK ) {
        for ( auto i = 0; i < num_groups; i++ ) {
            // The following condition follows what JRX does
            // internally as well: if not both are set, just skip (and
            // don't count) the group.
            if ( groups[i].rm_so >= 0 || groups[i].rm_eo >= 0 )
                captures.emplace_back(data.sub(groups[i].rm_so, groups[i].rm_eo).data());
        }
    }

    return captures;
}

void regexp::detail::CompiledRegExp::RegFree::operator()(jrx_regex_t* j) {
    jrx_regfree(j);
    delete j;
}

regexp::detail::CompiledRegExp::CompiledRegExp(const regexp::Patterns& patterns, regexp::Flags flags)
    : _flags(flags), _patterns(patterns) {
    _newJrx();

    if ( patterns.empty() )
        return;

    int idx = 0;
    for ( const auto& p : patterns )
        _compileOne(p, idx++);

    jrx_regset_finalize(jrx());
}

void regexp::detail::CompiledRegExp::_newJrx() {
    assert(! _jrx && "regexp already compiled");

    int cflags = (REG_EXTENDED | REG_ANCHOR | REG_LAZY); // | REG_DEBUG;

    if ( _flags.no_sub )
        cflags |= REG_NOSUB;
    else if ( _flags.use_std )
        cflags |= REG_STD_MATCHER;

    _patterns.clear();
    _jrx = std::unique_ptr<jrx_regex_t, RegFree>(new jrx_regex_t);
    jrx_regset_init(_jrx.get(), -1, cflags);
}

void regexp::detail::CompiledRegExp::_compileOne(regexp::Pattern pattern, int idx) {
    const auto& regexp = pattern.value();

    int cflags = (pattern.isCaseInsensitive() ? REG_ICASE : 0);
    auto id = static_cast<jrx_accept_id>(pattern.matchID());

    if ( auto rc = jrx_regset_add2(_jrx.get(), regexp.c_str(), regexp.size(), cflags, id); rc != REG_OK ) {
        static char err[256];
        jrx_regerror(rc, _jrx.get(), err, sizeof(err));
        throw PatternError(fmt("error compiling pattern '%s': %s", pattern, err));
    }

    _patterns.push_back(std::move(pattern));
}

RegExp::RegExp(const regexp::Patterns& patterns, regexp::Flags flags) {
    const auto& key = (patterns.empty() ? std::string() :
                                          join(transform(patterns, [](const auto& p) { return to_string(p); }), "|") +
                                              "|" + flags.cacheKey());
    auto& ptr = detail::globalState()->regexp_cache[key];

    if ( ! ptr )
        ptr = std::make_shared<regexp::detail::CompiledRegExp>(patterns, flags);

    _re = ptr;
}

RegExp::RegExp(regexp::Pattern pattern, regexp::Flags flags) : RegExp(regexp::Patterns{{std::move(pattern)}}, flags) {}

RegExp::RegExp() : RegExp(regexp::Patterns{}, regexp::Flags{}) {}

int32_t RegExp::match(const Bytes& data) const {
    jrx_match_state ms;
    jrx_accept_id acc = _search_pattern(&ms, data.data(), data.size(), nullptr, nullptr);
    jrx_match_state_done(&ms);
    return acc;
}

static Bytes _subslice(const Bytes& data, jrx_offset so, jrx_offset eo) {
    if ( so < 0 || eo < 0 )
        return Bytes();

    return Bytes(data.sub(data.begin() + so, data.begin() + eo));
}

Vector<Bytes> RegExp::matchGroups(const Bytes& data) const {
    assert(jrx() && "regexp not compiled");

    if ( _re->_patterns.size() > 1 )
        throw NotSupported("cannot capture groups during set matching");

    if ( _re->_flags.no_sub )
        throw NotSupported("cannot capture groups when compiled with &nosub");

    jrx_offset so = -1;
    jrx_offset eo = -1;
    jrx_match_state ms;
    auto rc = _search_pattern(&ms, data.data(), data.size(), &so, &eo);

    Vector<Bytes> groups;

    if ( rc > 0 ) {
        groups.emplace_back(_subslice(data, so, eo));

        if ( auto num_groups = jrx_num_groups(jrx()); num_groups > 1 ) {
            std::vector<jrx_regmatch_t> pmatch(num_groups);
            jrx_reggroups(jrx(), &ms, num_groups, pmatch.data());

            for ( int i = 1; i < num_groups; i++ ) {
                if ( pmatch[i].rm_so >= 0 )
                    groups.emplace_back(_subslice(data, pmatch[i].rm_so, pmatch[i].rm_eo));
            }
        }
    }

    jrx_match_state_done(&ms);
    return groups;
}

Tuple<int32_t, Bytes> RegExp::find(const Bytes& data) const {
    const auto* const startp = data.data();
    const auto* const endp = startp + data.size().Ref();

    int cur_rc = 0;
    jrx_offset cur_so = -1;
    jrx_offset cur_eo = -1;

    for ( const auto* cur = startp; cur < endp; cur++ ) {
        jrx_offset so = -1; // just initialize with something, will be set by search_pattern to >=0 on match
        jrx_offset eo = -1; // likewise
        jrx_match_state ms;
        auto rc = _search_pattern(&ms, cur, endp - cur, &so, &eo);

        if ( rc > 0 ) {
            assert(so >= 0 && eo >= 0);
            auto nlen = (eo - so);
            auto olen = (cur_eo - cur_so);
            so += static_cast<jrx_offset>(cur - startp);
            eo += static_cast<jrx_offset>(cur - startp);

            // Pick longest match, or left-most if same length.
            if ( nlen >= olen && (nlen > olen || so < cur_so || cur_so < 0) ) {
#ifdef _DEBUG_MATCHING
                std::cerr << fmt("=> better match rc=%d so=%d eo=%d\n", rc, so, eo);
#endif

                cur_rc = rc;
                cur_so = so;
                cur_eo = eo;
            }
        }

        jrx_match_state_done(&ms);
    }

    if ( cur_rc > 0 )
        return tuple::make(cur_rc, _subslice(data, cur_so, cur_eo));

    if ( cur_rc == 0 )
        cur_rc = -1; // for this method, adding more data may always help

    return tuple::make(cur_rc, ""_b);
}

regexp::MatchState RegExp::tokenMatcher() const { return regexp::MatchState(*this); }

jrx_accept_id RegExp::_search_pattern(jrx_match_state* ms, const char* data, size_t len, jrx_offset* so,
                                      jrx_offset* eo) const {
    if ( len == 0 ) {
        // Nothing to do, but still need to init the match state.
        jrx_match_state_init(jrx(), 0, ms);
        return -1;
    }

    const jrx_assertion last = JRX_ASSERTION_EOL | JRX_ASSERTION_EOD;
    jrx_assertion first = JRX_ASSERTION_BOL | JRX_ASSERTION_BOD;

    jrx_match_state_init(jrx(), 0, ms);
    jrx_accept_id rc = 0;

    auto use_std_matcher = _use_std_matcher(jrx(), ms);

#ifdef _DEBUG_MATCHING
    std::cerr << fmt("feeding |%s| use_std_matcher=%u first=%u last=%u\n", escapeBytes(std::string_view(data, len)),
                     use_std_matcher, first, last);
#endif

    if ( use_std_matcher )
        rc = static_cast<jrx_accept_id>(jrx_regexec_partial_std(jrx(), data, len, first, last, ms, true));
    else
        rc = static_cast<jrx_accept_id>(jrx_regexec_partial_min(jrx(), data, len, first, last, ms, true));

#ifdef _DEBUG_MATCHING
    std::cerr << fmt("-> rc=%d ms->offset=%d\n", rc, ms->offset);
#endif

    if ( rc > 0 ) {
        if ( use_std_matcher ) {
            jrx_regmatch_t pmatch;
            jrx_reggroups(jrx(), ms, 1, &pmatch);

            if ( so )
                *so = pmatch.rm_so; // 0-based

            if ( eo )
                *eo = pmatch.rm_eo; // 0-based
        }
        else {
            if ( so )
                *so = 0;

            if ( eo )
                *eo = ms->match_eo - 1; // 1-based
        }

#ifdef _DEBUG_MATCHING
        std::cerr << fmt("   ms->offset=%d so=%d eo=%d\n", ms->offset, so ? *so : -1, eo ? *eo : -1);
#endif
    }

    return rc;
}

std::string hilti::rt::detail::adl::to_string(const RegExp& x, adl::tag /*unused*/) {
    if ( x.patterns().empty() )
        return "<regexp w/o pattern>";

    auto p = join(transform(x.patterns(), [&](const auto& s) { return to_string(s); }), " | ");
    auto f = std::vector<std::string>();

    if ( x.flags().no_sub )
        f.emplace_back("&nosub");

    if ( f.empty() )
        return p;

    return fmt("%s %s", p, join(f, " "));
}
