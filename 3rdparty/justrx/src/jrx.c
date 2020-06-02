
#include "dfa-interpreter-min.h"
#include "dfa-interpreter-std.h"
#include "jrx-intern.h"

// Collects the right options based
static jrx_option _options(jrx_regex_t* preg)
{
    int cflags = preg->cflags;

    if ( ! (cflags & REG_EXTENDED) )
        preg->errmsg = "REG_BASIC syntax is not supported";

    if ( cflags & REG_ICASE )
        preg->errmsg = "REG_ICASE not supported at this time";

    if ( cflags & REG_NEWLINE )
        preg->errmsg = "REG_NEWLINE not supported at this time";

    if ( preg->errmsg )
        return REG_NOTSUPPORTED;

    jrx_option options = 0;

    if ( cflags & REG_DEBUG )
        options |= JRX_OPTION_DEBUG;

    if ( ! (cflags & REG_ANCHOR) )
        options |= JRX_OPTION_DONT_ANCHOR;

    if ( cflags & REG_NOSUB )
        options |= JRX_OPTION_NO_CAPTURE;
    else
        options |= JRX_OPTION_STD_MATCHER;

    if ( cflags & REG_STD_MATCHER )
        options |= JRX_OPTION_STD_MATCHER;

    if ( cflags & REG_LAZY )
        options |= JRX_OPTION_LAZY;

    if ( cflags & REG_FIRST_MATCH )
        options |= JRX_OPTION_FIRST_MATCH;

    return options;
}

static inline void _clear_pmatch(size_t nmatch, jrx_regmatch_t pmatch[], int first_zero)
{
    int i;
    for ( i = 0; i < nmatch; i++ )
        pmatch[i].rm_so = pmatch[i].rm_eo = -1;

    if ( first_zero && nmatch > 0 )
        pmatch[0].rm_so = pmatch[0].rm_eo = 0;
}

static inline jrx_match_accept _pick_accept(set_match_accept* accepts)
{
    jrx_match_accept result = {0, 0};
    jrx_offset min = JRX_OFFSET_MAX;
    jrx_offset min_len = 0;
    // We take the left-most match.
    set_for_each(match_accept, accepts, acc)
    {
        if ( ! acc.tags ) {
            if ( ! result.aid )
                result = acc;
            continue;
        }

        int len = acc.tags[1] - acc.tags[0];

        if ( acc.tags[0] < min || (acc.tags[0] == min && len > min_len) ) {
            result = acc;
            min = acc.tags[0];
            min_len = len;
        }
    }

    return result;
}

// Returns:
//
// 0: matching failed and can't be resumed.
// >0: accept with this ID (if multiple, it's undefined which).
// -1: partial but not full match yet.
static int _regexec_partial_std(const jrx_regex_t* preg, const char* buffer, unsigned int len,
                                jrx_assertion first, jrx_assertion last, jrx_match_state* ms,
                                int find_partial_matches)
{
    const char* p;
    for ( p = buffer; len; len-- ) {
        jrx_assertion assertions = JRX_ASSERTION_NONE;

        if ( p == buffer )
            assertions |= first;

        if ( len == 1 )
            assertions |= last;

        // We cast to uint8_t here first because otherwise the automatic cast
        // would appply sign extension and mistreat characters inside the
        // negative space.
        if ( jrx_match_state_advance(ms, (uint8_t)*p++, assertions) == 0 ) {
            jrx_match_accept acc = _pick_accept(ms->accepts);
            return acc.aid ? acc.aid : 0;
        }
    }

    if ( ! find_partial_matches && jrx_can_transition(ms) && ! (preg->cflags & REG_FIRST_MATCH) )
        return -1;

    jrx_match_accept acc = _pick_accept(ms->accepts);
    return acc.aid ? acc.aid : -1;
}

// Returns:
//
// 0: matching failed and can't be resumed.
// >0: accept with this ID (if multiple, it's undefined which).
// -1: partial but not full match yet.
static int _regexec_partial_min(const jrx_regex_t* preg, const char* buffer, unsigned int len,
                                jrx_assertion first, jrx_assertion last, jrx_match_state* ms,
                                int find_partial_matches)
{
    jrx_offset eo = ms->offset;

    const char* p;
    for ( p = buffer; len; --len ) {
        jrx_assertion assertions = JRX_ASSERTION_NONE;

        if ( p == buffer )
            assertions |= first;

        if ( len == 1 )
            assertions |= last;

        // We cast to uint8_t here first because otherwise the automatic cast
        // would appply sign extension and mistreat characters inside the
        // negative space.
        jrx_accept_id rc = jrx_match_state_advance_min(ms, (uint8_t)*p++, assertions);

        if ( ! rc ) {
            ms->offset = eo;
            return ms->acc > 0 ? ms->acc : 0;
        }

        if ( rc > 0 ) {
            eo = ms->offset;
            ms->acc = rc;

            if ( preg->cflags & REG_FIRST_MATCH || ! jrx_can_transition(ms) )
                return ms->acc;
        }
    }

    ms->offset = eo;

    if ( ! find_partial_matches && jrx_can_transition(ms) )
        return -1;

    return ms->acc;
}

void jrx_regset_init(jrx_regex_t* preg, int nmatch, int cflags)
{
    // Determine whether we will use the standard or the minimal matcher, and
    // if the former enforce the corresponding flag to be set.
    if ( nmatch != 0 && ! (cflags & REG_NOSUB) )
        cflags |= REG_STD_MATCHER;

    preg->re_nsub = 0;
    preg->nmatch = nmatch;
    preg->cflags = cflags;
    preg->nfa = 0;
    preg->dfa = 0;
    preg->errmsg = 0;
}

int jrx_regset_add(jrx_regex_t* preg, const char* pattern, unsigned int len)
{
    jrx_option options = _options(preg);

    if ( options == REG_NOTSUPPORTED )
        return REG_BADPAT;

    if ( ! preg->nfa )
        preg->nfa = nfa_compile(pattern, len, options, preg->nmatch, &preg->errmsg);

    else {
        preg->nfa = nfa_compile_add(preg->nfa, pattern, len, &preg->errmsg);
        nfa_remove_epsilons(preg->nfa);
    }

    return preg->errmsg ? REG_BADPAT : REG_OK;
}

int jrx_regset_finalize(jrx_regex_t* preg)
{
    jrx_dfa* dfa = dfa_from_nfa(preg->nfa);
    if ( ! dfa )
        return REG_EMEM;

    preg->dfa = dfa;
    preg->re_nsub = dfa->max_capture;

    return REG_OK;
}

int jrx_regcomp(jrx_regex_t* preg, const char* pattern, int cflags)
{
    jrx_regset_init(preg, -1, cflags);

    int rc = jrx_regset_add(preg, pattern, strlen(pattern));
    if ( rc != REG_OK )
        return rc;

    return jrx_regset_finalize(preg);
}

// Returns:
//
// 0: matching failed and can't be resumed.
// >0: accept with this ID (if multiple, it's undefined which).
// -1: partial but not full match yet.
int jrx_regexec_partial(const jrx_regex_t* preg, const char* buffer, unsigned int len,
                        jrx_assertion first, jrx_assertion last, jrx_match_state* ms,
                        int find_partial_matches)
{
    int rc = 0;

    if ( preg->cflags & REG_STD_MATCHER )
        rc = _regexec_partial_std(preg, buffer, len, first, last, ms, find_partial_matches);
    else
        rc = _regexec_partial_min(preg, buffer, len, first, last, ms, find_partial_matches);

    return rc;
}

int jrx_reggroups(const jrx_regex_t* preg, jrx_match_state* ms, size_t nmatch,
                  jrx_regmatch_t pmatch[])
{
    if ( ! (preg->cflags & REG_STD_MATCHER) || (preg->dfa->options & JRX_OPTION_NO_CAPTURE) ) {
        _clear_pmatch(nmatch, pmatch, 1);
        return REG_OK; // Fail silently.
    }

    if ( ! set_match_accept_size(ms->accepts) ) {
        _clear_pmatch(nmatch, pmatch, 0);
        return REG_NOMATCH;
    }

    jrx_match_accept acc = _pick_accept(ms->accepts);
    jrx_offset* tags = acc.tags;
    assert(tags);

    int i;

    for ( i = 0; i < nmatch; i++ ) {
        if ( i <= preg->dfa->max_capture && i * 2 + 1 <= preg->dfa->max_tag && tags[i * 2] > 0 &&
             tags[i * 2 + 1] > 0 ) {
            pmatch[i].rm_so = ms->begin + tags[i * 2] - 1;
            pmatch[i].rm_eo = ms->begin + tags[i * 2 + 1] - 1;
        }
        else
            pmatch[i].rm_so = pmatch[i].rm_eo = -1;
    }

    return REG_OK;
}

int jrx_regexec(const jrx_regex_t* preg, const char* string, size_t nmatch, jrx_regmatch_t pmatch[],
                int eflags)
{
    if ( eflags & (REG_NOTEOL | REG_NOTBOL) )
        return REG_NOTSUPPORTED;

    if ( ! (string && *string) ) {
        _clear_pmatch(nmatch, pmatch, 1);
        return 0;
    }

    jrx_match_state ms;
    jrx_match_state_init(preg, 0, &ms);

    jrx_assertion first = JRX_ASSERTION_BOL | JRX_ASSERTION_BOD;
    jrx_assertion last = JRX_ASSERTION_EOL | JRX_ASSERTION_EOD;

    int rc = jrx_regexec_partial(preg, string, strlen(string), first, last, &ms, 1);

    if ( rc <= 0 ) {
        jrx_match_state_done(&ms);
        return REG_NOMATCH;
    }

    rc = jrx_reggroups(preg, &ms, nmatch, pmatch);
    jrx_match_state_done(&ms);
    return rc;
}

void jrx_regfree(jrx_regex_t* preg)
{
    if ( preg->nfa )
        nfa_delete(preg->nfa);

    if ( preg->dfa )
        dfa_delete(preg->dfa);
}

size_t jrx_regerror(int errcode, const jrx_regex_t* preg, char* errbuf, size_t errbuf_size)
{
    char buffer[127];

    const char* msg = 0;
    switch ( errcode ) {
    case REG_NOTSUPPORTED:
        msg = "feature not supported";
        break;

    case REG_BADPAT:
        msg = "bad pattern";
        break;

    case REG_NOMATCH:
        msg = "no match";
        break;

    default:
        msg = "unknown error code for regerror()";
    }

    if ( preg->errmsg ) {
        snprintf(buffer, sizeof(buffer), "%s: %s", msg, preg->errmsg);
        msg = buffer;
    }

    if ( errbuf && errbuf_size ) {
        strncpy(errbuf, msg, errbuf_size);
        errbuf[errbuf_size - 1] = '\0';
    }

    return strlen(msg);
}

int jrx_num_groups(jrx_regex_t* preg)
{
    return preg->dfa->max_capture + 1;
}

int jrx_is_anchored(jrx_regex_t* preg)
{
    jrx_nfa_state* initial = preg->nfa->initial;

    if ( ! initial )
        return 0;

    vec_for_each(nfa_transition, initial->trans, trans)
    {
        jrx_ccl* ccl = vec_ccl_get(preg->nfa->ctx->ccls->ccls, trans.ccl);
        if ( ! (ccl->assertions & JRX_ASSERTION_BOL) )
            return 0;
    }

    return 1;
}

int jrx_can_transition(jrx_match_state* ms)
{
    jrx_dfa_state* state = vec_dfa_state_get(ms->dfa->states, ms->state);

    if ( ! state ) {
        if ( ms->dfa->options & JRX_OPTION_DEBUG )
            fprintf(stderr, "> can_transition: 0\n");

        return 0;
    }

    int can = vec_dfa_transition_size(state->trans);
    if ( ms->dfa->options & JRX_OPTION_DEBUG )
        fprintf(stderr, "> can_transition: %d (%d)\n", (can != 0), can);

    return can;
}

int jrx_current_accept(jrx_match_state* ms)
{
    if ( (ms->dfa->options & JRX_OPTION_STD_MATCHER) ) {
        if ( ! ms->accepts )
            return 0;

        jrx_match_accept acc = _pick_accept(ms->accepts);
        return acc.aid ? acc.aid : 0;
    }


    jrx_dfa_state* state = dfa_get_state(ms->dfa, ms->state);
    return state->accepts ? vec_dfa_accept_get(state->accepts, 0).aid : 0;
}
