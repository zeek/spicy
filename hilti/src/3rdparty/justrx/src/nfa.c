// $Id$

#include "nfa.h"
#include "jrx-intern.h"

#include <justrx/autogen/re-parse.h>
#include <justrx/autogen/re-scan.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/** \addtogroup NFA */
//@{



static jrx_nfa_state* _nfa_state_create(jrx_nfa_context* ctx)
{
    jrx_nfa_state* state = (jrx_nfa_state*)malloc(sizeof(jrx_nfa_state));
    if ( ! state )
        return 0;

    state->id = vec_nfa_state_append(ctx->states, state);
    state->accepts = 0;
    state->trans = vec_nfa_transition_create(0);
    return state;
}

// Not exposed. Delete the context instead.
static void _nfa_state_delete(jrx_nfa_state* state)
{
    vec_for_each(nfa_transition, state->trans, trans)
    {
        if ( trans.tags )
            set_tag_delete(trans.tags);
    }

    vec_nfa_transition_delete(state->trans);

    if ( state->accepts ) {
        vec_for_each(nfa_accept, state->accepts, acc)
        {
            if ( acc.tags )
                set_tag_delete(acc.tags);
        }

        vec_nfa_accept_delete(state->accepts);
    }

    free(state);
}

static void _nfa_state_closure(jrx_nfa_context* ctx, jrx_nfa_state* state,
                               set_nfa_state_id* closure)
{
    if ( set_nfa_state_id_contains(closure, state->id) )
        return;

    set_nfa_state_id_insert(closure, state->id);

    vec_for_each(nfa_transition, state->trans, trans)
        _nfa_state_closure(ctx, vec_nfa_state_get(ctx->states, trans.succ), closure);
}

static jrx_nfa_state* _nfa_state_deep_copy(jrx_nfa_context* ctx, jrx_nfa_state* state,
                                           vec_nfa_state* copies)
{
    jrx_nfa_state* copy = vec_nfa_state_get(copies, state->id);

    if ( copy )
        return copy;

    copy = _nfa_state_create(ctx);

    if ( ! copy )
        return 0;

    vec_nfa_state_set(copies, state->id, copy);

    copy->accepts = state->accepts ? vec_nfa_accept_copy(state->accepts) : 0;

    vec_for_each(nfa_transition, state->trans, trans)
    {
        jrx_nfa_state* succ = vec_nfa_state_get(ctx->states, trans.succ);
        jrx_nfa_state* nsucc = _nfa_state_deep_copy(ctx, succ, copies);

        assert(nsucc);
        jrx_nfa_transition ntrans = {trans.ccl, nsucc->id,
                                     trans.tags ? set_tag_copy(trans.tags) : 0};
        vec_nfa_transition_append(copy->trans, ntrans);
    }

    return copy;
}

static void _nfa_state_add_trans(jrx_nfa_state* state, jrx_nfa_state* succ, set_tag* tags,
                                 jrx_ccl* ccl)
{
    assert(succ && state && state->trans);
    jrx_nfa_transition ntrans = {ccl->id, succ->id, tags ? set_tag_copy(tags) : 0};
    vec_nfa_transition_append(state->trans, ntrans);
}

static jrx_nfa* _nfa_deep_copy(jrx_nfa* nfa)
{
    vec_nfa_state* copies = vec_nfa_state_create(0);

    jrx_nfa_state* ninitial = _nfa_state_deep_copy(nfa->ctx, nfa->initial, copies);
    jrx_nfa_state* nfinal = _nfa_state_deep_copy(nfa->ctx, nfa->final, copies);

    jrx_nfa* copy = nfa_create(nfa->ctx, ninitial, nfinal);
    copy->initial_tags = nfa->initial_tags ? set_tag_copy(nfa->initial_tags) : 0;

    vec_nfa_state_delete(copies);

    return copy;
}

jrx_nfa_context* nfa_context_create(jrx_option options, int8_t nmatch)
{
    jrx_nfa_context* ctx = (jrx_nfa_context*)malloc(sizeof(jrx_nfa_context));
    ctx->refcnt = 0;
    ctx->options = options;
    ctx->nmatch = nmatch >= 0 ? nmatch : INT8_MAX;
    ctx->max_tag = -1;
    ctx->max_capture = 0; // We always have one implicitly. This is adjusted only by re_parse.y
    ctx->max_accept = 0;  // 0 is "no accept".
    ctx->ccls = ccl_group_create();
    ctx->states = vec_nfa_state_create(0);
    return ctx;
}

void nfa_context_delete(jrx_nfa_context* ctx)
{
    if ( ! ctx )
        return;

    ccl_group_delete(ctx->ccls);

    vec_for_each(nfa_state, ctx->states, state) _nfa_state_delete(state);

    vec_nfa_state_delete(ctx->states);
    free(ctx);
}

jrx_nfa* nfa_create(jrx_nfa_context* ctx, jrx_nfa_state* initial, jrx_nfa_state* final)
{
    jrx_nfa* nfa = (jrx_nfa*)malloc(sizeof(jrx_nfa));
    nfa->ctx = ctx;
    nfa->initial_tags = 0;
    nfa->initial = initial;
    nfa->final = final;
    ++ctx->refcnt;
    return nfa;
}

void nfa_delete(jrx_nfa* nfa)
{
    if ( ! nfa )
        return;

    if ( --nfa->ctx->refcnt == 0 )
        nfa_context_delete(nfa->ctx);

    if ( nfa->initial_tags )
        set_tag_delete(nfa->initial_tags);

    free(nfa);
}

jrx_nfa* nfa_set_accept(jrx_nfa* nfa, jrx_accept_id accept)
{
    assert(nfa->initial && nfa->final);

    jrx_nfa_accept acc = {0, accept, 0};

    if ( ! nfa->final->accepts )
        nfa->final->accepts = vec_nfa_accept_create(0);

    vec_nfa_accept_append(nfa->final->accepts, acc);

    if ( accept > nfa->ctx->max_accept )
        nfa->ctx->max_accept = accept;

    return nfa;
}

jrx_nfa* nfa_set_capture(jrx_nfa* nfa, uint8_t group)
{
    assert(nfa->initial && nfa->final);
    jrx_nfa_context* ctx = nfa->ctx;

    if ( group >= ctx->nmatch )
        // Uninteresting group.
        return nfa;

    if ( group * 2 + 1 > ctx->max_tag )
        ctx->max_tag = group * 2 + 1;

    if ( ! nfa->initial_tags )
        nfa->initial_tags = set_tag_create(0);

    jrx_nfa* eps = nfa_empty(ctx);
    eps->initial_tags = set_tag_create(0);

    jrx_tag t1 = {group * 2, -5};
    jrx_tag t2 = {group * 2 + 1, 5};

    set_tag_insert(nfa->initial_tags, t1);
    set_tag_insert(eps->initial_tags, t2);

    jrx_nfa* nnfa = nfa_concat(nfa, eps, 0);

    return nnfa;
}

jrx_nfa* nfa_empty(jrx_nfa_context* ctx)
{
    jrx_nfa_state* s = _nfa_state_create(ctx);
    jrx_nfa* nfa = nfa_create(ctx, s, s);
    return nfa;
}

jrx_nfa* nfa_from_ccl(jrx_nfa_context* ctx, jrx_ccl* ccl)
{
    jrx_nfa* nfa1 = nfa_empty(ctx);
    jrx_nfa* nfa2 = nfa_empty(ctx);
    return nfa_concat(nfa1, nfa2, ccl);
}

jrx_nfa* nfa_concat(jrx_nfa* nfa1, jrx_nfa* nfa2, jrx_ccl* ccl)
{
    assert(nfa1->ctx == nfa2->ctx);
    jrx_nfa_context* ctx = nfa1->ctx;

    if ( ! ccl )
        ccl = ccl_epsilon(ctx->ccls);

    _nfa_state_add_trans(nfa1->final, nfa2->initial, nfa2->initial_tags, ccl);
    nfa1->final = nfa2->final;

    nfa2->initial = 0;
    nfa2->final = 0;
    nfa_delete(nfa2);

    return nfa1;
}

jrx_nfa* nfa_alternative(jrx_nfa* nfa1, jrx_nfa* nfa2)
{
    assert(nfa1->ctx == nfa2->ctx);
    jrx_nfa_context* ctx = nfa1->ctx;

    jrx_nfa_state* eps1 = _nfa_state_create(ctx);
    _nfa_state_add_trans(eps1, nfa1->initial, nfa1->initial_tags, ccl_epsilon(ctx->ccls));
    _nfa_state_add_trans(eps1, nfa2->initial, nfa2->initial_tags, ccl_epsilon(ctx->ccls));

    jrx_nfa_state* eps2 = _nfa_state_create(ctx);
    _nfa_state_add_trans(nfa1->final, eps2, 0, ccl_epsilon(ctx->ccls));
    _nfa_state_add_trans(nfa2->final, eps2, 0, ccl_epsilon(ctx->ccls));

    jrx_nfa* nfa = nfa_create(ctx, eps1, eps2);

    nfa_delete(nfa1);

    if ( nfa1 != nfa2 )
        nfa_delete(nfa2);

    return nfa;
}

jrx_nfa* nfa_iterate(jrx_nfa* nfa, int min, int max)
{
    assert(max >= min || max == -1);

    jrx_nfa_context* ctx = nfa->ctx;
    jrx_nfa* templ = _nfa_deep_copy(nfa);

    if ( min < 0 )
        min = 0;

    if ( min == 0 && max == 0 ) {
        nfa_delete(nfa);
        return nfa_empty(ctx);
    }

    jrx_nfa* all = 0;

    if ( min > 1 ) {
        all = nfa;
        int i;
        for ( i = 0; i < min - 1; i++ )
            all = nfa_concat(all, _nfa_deep_copy(templ), 0);
    }
    else
        nfa_delete(nfa);

    if ( max >= 0 ) {
        jrx_nfa* optional = nfa_alternative(_nfa_deep_copy(templ), nfa_empty(ctx));

        int i;
        for ( i = max - min; i > 0; i-- )
            all = all ? nfa_concat(all, _nfa_deep_copy(optional), 0) : optional;
    }

    else {
        jrx_nfa* closure = _nfa_deep_copy(templ);
        _nfa_state_add_trans(closure->final, closure->initial, /* closure->initial_tags */ 0,
                             ccl_epsilon(ctx->ccls));
        all = all ? nfa_concat(all, closure, 0) : closure;
    }

    if ( min == 0 ) {
        jrx_nfa* optional = nfa_alternative(all, nfa_empty(ctx));
        all = optional;
    }

    nfa_delete(templ);
    return all;
}

void _nfa_state_follow_epsilons(jrx_nfa_context* ctx, jrx_nfa_state* state,
                                set_nfa_state_id* closure, vec_nfa_transition* ntrans,
                                set_tag** tags, vec_nfa_accept** accepts, jrx_assertion assertions)
{
    if ( ! state )
        return;

    if ( set_nfa_state_id_contains(closure, state->id) )
        return;

    set_nfa_state_id_insert(closure, state->id);

    if ( state->accepts && state->accepts != *accepts ) {
        vec_for_each(nfa_accept, state->accepts, acc)
        {
            set_tag* ntags = 0;

            if ( acc.tags || *tags ) {
                ntags = set_tag_create(0);

                if ( acc.tags )
                    set_tag_join(ntags, acc.tags);

                if ( *tags )
                    set_tag_join(ntags, *tags);
            }

            if ( ! *accepts )
                *accepts = vec_nfa_accept_create(0);

            jrx_nfa_accept nacc = {acc.assertions | assertions, acc.aid, ntags};
            vec_nfa_accept_append(*accepts, nacc);
        }
    }

    vec_for_each(nfa_transition, state->trans, trans)
    {
        jrx_ccl* ccl = vec_ccl_get(ctx->ccls->ccls, trans.ccl);

        if ( ! ccl_is_epsilon(ccl) ) {
            // Add a new transition to this state.
            ccl = ccl_add_assertions(ccl, assertions);

            if ( trans.tags ) {
                if ( ! *tags )
                    *tags = set_tag_create(0);

                set_tag_join(*tags, trans.tags);
            }

            jrx_nfa_transition t = {ccl->id, trans.succ, *tags ? set_tag_copy(*tags) : 0};
            vec_nfa_transition_append(ntrans, t);
        }

        else {
            // Another epsilon transition, recurse.
            set_tag* ntags = *tags ? set_tag_copy(*tags) : 0;

            if ( trans.tags ) {
                if ( ! ntags )
                    ntags = set_tag_copy(trans.tags);
                else
                    set_tag_join(ntags, trans.tags);
            }

            jrx_nfa_state* succ = vec_nfa_state_get(ctx->states, trans.succ);

            _nfa_state_follow_epsilons(ctx, succ, closure, ntrans, &ntags, accepts,
                                       assertions | ccl->assertions);

            if ( ntags )
                set_tag_delete(ntags);
        }
    }
}

void nfa_remove_epsilons(jrx_nfa* nfa)
{
    jrx_nfa_context* ctx = nfa->ctx;

    vec_for_each(nfa_state, ctx->states, state)
    {
        vec_nfa_transition* ntrans = vec_nfa_transition_create(0);

        vec_for_each(nfa_transition, state->trans, trans)
        {
            jrx_ccl* ccl = vec_ccl_get(ctx->ccls->ccls, trans.ccl);

            if ( ! ccl_is_epsilon(ccl) ) {
                // Keep transition.n
                jrx_nfa_transition t = {trans.ccl, trans.succ,
                                        trans.tags ? set_tag_copy(trans.tags) : 0};
                vec_nfa_transition_append(ntrans, t);
            }

            else {
                // Collect all states (plus all tags/accepts/assertions_
                // along the way) that we can reach by epsilon transitions
                // only.
                set_nfa_state_id* closure = set_nfa_state_id_create(0);
                set_tag* tags = trans.tags ? set_tag_copy(trans.tags) : 0;

                jrx_nfa_state* succ = vec_nfa_state_get(ctx->states, trans.succ);
                _nfa_state_follow_epsilons(ctx, succ, closure, ntrans, &tags, &state->accepts,
                                           ccl->assertions);

                set_nfa_state_id_delete(closure);

                if ( tags ) {
                    if ( state == nfa->initial ) {
                        if ( ! nfa->initial_tags )
                            nfa->initial_tags = set_tag_copy(tags);
                        else
                            set_tag_join(nfa->initial_tags, tags);
                    }

                    set_tag_delete(tags);
                }
            }
        }

        vec_for_each(nfa_transition, state->trans, t)
        {
            if ( t.tags )
                set_tag_delete(t.tags);
        }

        vec_nfa_transition_delete(state->trans);

        state->trans = ntrans;
    }
}

static jrx_nfa* _nfa_compile_pattern(jrx_nfa_context* ctx, const char* pattern, int len,
                                     const char** errmsg)
{
    yyscan_t scanner;
    jrx_nfa* nfa = 0;

    RE_lex_init(&scanner);
    // FIXME: This assumes that there aren't null bytes in there ...
    RE__scan_bytes(pattern, len, scanner);

    const char* internal_errmsg = 0;

    RE_set_extra(&internal_errmsg, scanner);

    int i = RE_parse(scanner, ctx, &nfa);

    RE_lex_destroy(scanner);

    if ( i == 1 && ! internal_errmsg )
        internal_errmsg = "parser error";

    if ( i == 2 )
        internal_errmsg = "out of memory during parsing";

    if ( internal_errmsg ) {
        nfa_context_delete(ctx);
        ctx = 0;

        if ( errmsg )
            *errmsg = internal_errmsg;

        return 0;
    }

    assert(nfa);

    // We take the next available accept IDs if we don't have one set yet.
    if ( ! nfa->final->accepts )
        nfa = nfa_set_accept(nfa, ++ctx->max_accept);

    if ( ctx->options & JRX_OPTION_DEBUG )
        nfa_print(nfa, stderr);

    nfa_remove_epsilons(nfa);

    if ( ctx->options & JRX_OPTION_DEBUG )
        nfa_print(nfa, stderr);

    return nfa;
}

jrx_nfa* nfa_compile_add(jrx_nfa* nfa, const char* pattern, int len, const char** errmsg)
{
#if 0
    if ( ! (nfa->ctx->options & JRX_OPTION_NO_CAPTURE) ) {
        *errmsg = "cannot capture subgroups with set matching; use OPTION_NO_CAPTURE";
        nfa_delete(nfa);
        return 0;
    }
#endif

    jrx_nfa* nnfa = _nfa_compile_pattern(nfa->ctx, pattern, len, errmsg);
    if ( ! nnfa ) {
        nfa_delete(nfa);
        return 0;
    }

    return nfa_alternative(nfa, nnfa);
}

jrx_nfa* nfa_compile(const char* pattern, int len, jrx_option options, int8_t nmatch,
                     const char** errmsg)
{
    if ( options & JRX_OPTION_NO_CAPTURE )
        nmatch = 0;

    jrx_nfa_context* ctx = nfa_context_create(options, nmatch);
    return _nfa_compile_pattern(ctx, pattern, len, errmsg);
}

static void _set_tag_print(set_tag* tags, FILE* file)
{
    if ( ! tags ) {
        fputs("none", file);
        return;
    }

    int first = 1;
    set_for_each(tag, tags, tag)
    {
        if ( ! first )
            fputs(",", file);
        fprintf(file, "%d@%d", tag.reg, tag.prio);
        first = 0;
    }
}

void nfa_state_print(jrx_nfa_context* ctx, jrx_nfa_state* state, FILE* file)
{
    fprintf(file, "state %d\n", state->id);

    if ( state->accepts ) {
        fprintf(file, "  accepts with");
        vec_for_each(nfa_accept, state->accepts, acc)
        {
            fprintf(file, " %d, tags", acc.aid);
            _set_tag_print(acc.tags, file);
            fprintf(file, ", final assertions %d", acc.assertions);
        }

        fprintf(file, "\n");
    }

    vec_for_each(nfa_transition, state->trans, trans)
    {
        ccl_print(vec_ccl_get(ctx->ccls->ccls, trans.ccl), file);
        fprintf(file, "   -> %d ", trans.succ);
        fputs("(tags ", file);
        _set_tag_print(trans.tags, file);
        fputs(")", file);
        fputs("\n", file);
    }
}

void nfa_print(jrx_nfa* nfa, FILE* file)
{
    // We compute a closure to print only relevant states.
    set_nfa_state_id* closure = set_nfa_state_id_create(0);
    _nfa_state_closure(nfa->ctx, nfa->initial, closure);

    fprintf(file, "== NFA with %d used states\n", set_nfa_state_id_size(closure));

    if ( nfa->initial_tags ) {
        fprintf(stderr, "  initial tags ");
        _set_tag_print(nfa->initial_tags, file);
        fprintf(stderr, "\n");
    }

    set_for_each(nfa_state_id, closure, nid)
    {
        jrx_nfa_state* state = vec_nfa_state_get(nfa->ctx->states, nid);
        assert(state);

        nfa_state_print(nfa->ctx, state, file);

        if ( state == nfa->initial )
            fputs("  -> initial state\n", file);

        if ( state == nfa->final )
            fputs("  -> final state\n", file);

        fputc('\n', file);
    }

    set_nfa_state_id_delete(closure);

    if ( ! nfa->ctx->ccls )
        return;

    fputs("CCLs:\n", file);
    ccl_group_print(nfa->ctx->ccls, file);
    fputs("\n", file);
}

//@}
