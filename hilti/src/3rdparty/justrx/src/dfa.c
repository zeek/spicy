// $Id$

#include "dfa.h"
#include "jrx-intern.h"

static jrx_dfa* _dfa_create()
{
    jrx_dfa* dfa = (jrx_dfa*)malloc(sizeof(jrx_dfa));
    if ( ! dfa )
        return 0;

    dfa->options = 0;
    dfa->nmatch = 0;
    dfa->initial = 0;
    dfa->initial_dstate = 0;
    dfa->states = vec_dfa_state_create(0);
    dfa->state_elems = vec_dfa_state_elem_create(0);
    dfa->hstates = kh_init(dfa_state_elem);
    dfa->ccls = 0;
    dfa->max_capture = -1;
    dfa->max_tag = -1;
    dfa->nfa = 0;

    return dfa;
}

static jrx_dfa_state* _dfa_state_create()
{
    jrx_dfa_state* dstate = (jrx_dfa_state*)malloc(sizeof(jrx_dfa_state));
    if ( ! dstate )
        return 0;

    dstate->accepts = 0;
    dstate->trans = vec_dfa_transition_create(0);
    return dstate;
}

static void _dfa_state_delete(jrx_dfa_state* state)
{
    vec_for_each(dfa_transition, state->trans, trans)
    {
        if ( trans.tops )
            vec_tag_op_delete(trans.tops);
    }

    vec_dfa_transition_delete(state->trans);

    if ( state->accepts ) {
        vec_for_each(dfa_accept, state->accepts, acc)
        {
            if ( acc.final_ops )
                vec_tag_op_delete(acc.final_ops);

            if ( acc.tags )
                free(acc.tags);
        }

        vec_dfa_accept_delete(state->accepts);
    }

    free(state);
}

static jrx_dfa_state_id reserve_dfastate_id(jrx_dfa* dfa, set_dfa_state_elem* dstate)
{
    jrx_dfa_state_id id = vec_dfa_state_append(dfa->states, 0);
    vec_dfa_state_elem_append(dfa->state_elems, 0);

    assert(dstate);

    int ret;
    khiter_t k = kh_put(dfa_state_elem, dfa->hstates, *dstate, &ret);
    // I'm not quite sure what ret==0 signals but kh_del() seems to be be the
    // idiom to use in that case ...
    if ( ! ret )
        kh_del(dfa_state_elem, dfa->hstates, k);

    kh_value(dfa->hstates, k) = id;
    return id;
}

// This is similar to tag_op but also carries the NFA state ID for later
// disambiguation.
typedef struct {
    jrx_nfa_state_id nid;
    jrx_tag_group_id told;
    jrx_tag_group_id tnew;
    jrx_tag tag;
} _nid_tag_op;

DECLARE_VECTOR(nid_tag_op, _nid_tag_op, uint32_t)

static set_dfa_state_elem* transition_with(jrx_nfa_context* ctx, jrx_dfa* dfa,
                                           set_dfa_state_elem* dstate, jrx_ccl* ccl,
                                           vec_tag_op** tops)
{
    set_nfa_state_id* nstates = set_nfa_state_id_create(0);
    vec_nid_tag_op* ntops = vec_nid_tag_op_create(0);

    jrx_tag_group_id tid = 0;

    // Get all our options with this CCL.

    set_for_each(dfa_state_elem, dstate, delem)
    {
        jrx_nfa_state* nstate = vec_nfa_state_get(ctx->states, delem.nid);

        vec_for_each(nfa_transition, nstate->trans, trans)
        {
            jrx_ccl* nccl = vec_ccl_get(ctx->ccls->ccls, trans.ccl);
            if ( ccl_do_intersect(nccl, ccl) ) {
                set_nfa_state_id_insert(nstates, trans.succ);

                ++tid;

                if ( trans.tags ) {
                    // Make sure we get at least one entry for this state.
                    assert(set_tag_size(trans.tags));

                    set_for_each(tag, trans.tags, tag)
                    {
                        _nid_tag_op ntop = {trans.succ, delem.tid, tid, tag};
                        vec_nid_tag_op_append(ntops, ntop);
                    }
                }

                else {
                    // Just record a copy operation.
                    _nid_tag_op ntop = {trans.succ, delem.tid, tid, {-1, 0}};
                    vec_nid_tag_op_append(ntops, ntop);
                }
            }
        }
    }

    // Now pick the right tag operations, using tag priorities to
    // disambiguate if necessary.

    set_dfa_state_elem* ndstate = set_dfa_state_elem_create(0);

    set_for_each(nfa_state_id, nstates, nid)
    {
        // Determine tag set with highest priority for this state.
        int8_t max_tprio = -127;
        jrx_tag_group_id max_tnew = 0;

        vec_for_each(nid_tag_op, ntops, ntop)
        {
            if ( ntop.nid == nid && ntop.tag.prio >= max_tprio ) {
                max_tprio = ntop.tag.prio;
                max_tnew = ntop.tnew;
            }
        }

        // Add those entries with the highest priority.
        vec_for_each(nid_tag_op, ntops, ntop2)
        {
            if ( ntop2.nid != nid )
                continue;

            if ( ntop2.tnew == max_tnew ) {
                dfa_state_elem delem = {nid, ntop2.tnew};
                set_dfa_state_elem_insert(ndstate, delem);

                if ( ! *tops )
                    *tops = vec_tag_op_create(0);

                jrx_tag_op nntop = {ntop2.told, ntop2.tnew, ntop2.tag.reg};
                vec_tag_op_append(*tops, nntop);
            }
        }
    }

    set_nfa_state_id_delete(nstates);
    vec_nid_tag_op_delete(ntops);

    return ndstate;
}

static jrx_dfa_state sentinel; // Value is irrelevant.

int dfa_state_compute(jrx_nfa_context* ctx, jrx_dfa* dfa, jrx_dfa_state_id id,
                      set_dfa_state_elem* dstate, int recurse)
{
    if ( vec_dfa_state_get(dfa->states, id) )
        // Already computed (or being worked on at the moment).
        return 1;

    // We set the pointer for the state we are currently computing to a dummy
    // value as an indicator that we're already working on it, to abort
    // recursion when we get to it again.
    vec_dfa_state_set(dfa->states, id, &sentinel);
    // vec_dfa_state_elem_set(dfa->state_elems, id, 0);

    // Determine the transitions for all CCLs.
    //
    // FIXME: I guess we could precompute the relevant CCLs here, instead of
    // trying all of them each time.
    vec_dfa_transition* transitions = vec_dfa_transition_create(0);

    vec_for_each(ccl, dfa->ccls->ccls, ccl)
    {
        if ( ccl_is_empty(ccl) )
            continue;

        // Determine which states we can reach with this CCL, including the
        // necessary tag operations to get there.
        vec_tag_op* tops = 0;
        set_dfa_state_elem* succ_dstate = transition_with(ctx, dfa, dstate, ccl, &tops);

        if ( set_dfa_state_elem_size(succ_dstate) == 0 ) {
            // Well, none.
            if ( tops )
                vec_tag_op_delete(tops);

            set_dfa_state_elem_delete(succ_dstate);
            continue;
        }

        // Do we already know that set of DFA states?
        jrx_dfa_state_id succ_id;
        int8_t old = 0;

        khiter_t k = kh_get(dfa_state_elem, dfa->hstates, *succ_dstate);
        if ( k != kh_end(dfa->hstates) ) {
            // Yes, use the old one.
            set_dfa_state_elem_delete(succ_dstate);
            succ_id = kh_value(dfa->hstates, k);
            succ_dstate = &kh_key(dfa->hstates, k);
            old = 1;
        }
        else
            // No, get a new ID for it.
            succ_id = reserve_dfastate_id(dfa, succ_dstate);

        // Record a transition for this CCL.
        jrx_dfa_transition trans = {ccl->id, succ_id, tops};
        vec_dfa_transition_append(transitions, trans);

        // Recurse if we are asked to do so.
        if ( recurse ) {
            dfa_state_compute(ctx, dfa, succ_id, succ_dstate, 1);
            // set_dfa_state_elem_delete(succ_dstate);
        }

        else {
            if ( ! old )
                // Records state for lazy computation.
                vec_dfa_state_elem_set(dfa->state_elems, succ_id, succ_dstate);
        }
    }

    // Now build the DFA state.
    jrx_dfa_state* dfastate = _dfa_state_create();

    if ( dfastate->trans )
        vec_dfa_transition_delete(dfastate->trans);

    dfastate->trans = transitions;

    // Add accepts.
    vec_dfa_accept* accepts = 0;

    set_for_each(dfa_state_elem, dstate, delem)
    {
        jrx_nfa_state* nstate = vec_nfa_state_get(ctx->states, delem.nid);

        if ( ! nstate->accepts )
            continue;

        vec_for_each(nfa_accept, nstate->accepts, acc)
        {
            vec_tag_op* tops = 0;

            if ( acc.tags ) {
                tops = vec_tag_op_create(0);
                set_for_each(tag, acc.tags, tag)
                {
                    jrx_tag_op top = {delem.tid, delem.tid, tag.reg};
                    vec_tag_op_append(tops, top);
                }
            }

            if ( ! accepts )
                accepts = vec_dfa_accept_create(0);

            jrx_dfa_accept dacc = {acc.assertions, acc.aid, delem.tid, tops, 0};
            vec_dfa_accept_append(accepts, dacc);
        }
    }

    dfastate->accepts = accepts;

    vec_dfa_state_set(dfa->states, id, dfastate);
    return 1;
}

jrx_dfa_state* dfa_get_state(jrx_dfa* dfa, jrx_dfa_state_id id)
{
    jrx_dfa_state* state = vec_dfa_state_get(dfa->states, id);

    if ( state )
        return state;

    set_dfa_state_elem* dstate = vec_dfa_state_elem_get(dfa->state_elems, id);
    assert(dstate);

    dfa_state_compute(dfa->nfa->ctx, dfa, id, dstate, 0);

    state = vec_dfa_state_get(dfa->states, id);
    assert(state);
    return state;
}

jrx_dfa* dfa_from_nfa(jrx_nfa* nfa)
{
    jrx_dfa* dfa = _dfa_create();
    if ( ! dfa )
        return 0;

    jrx_nfa_context* ctx = nfa->ctx;

    dfa->options = ctx->options;
    dfa->nmatch = ctx->nmatch;
    dfa->max_capture = ctx->max_capture;
    dfa->max_tag = ctx->max_tag;
    dfa->nfa = nfa;

    // Get us all the CCLs which are used in the NFA.
    dfa->ccls = ccl_group_create();

    vec_for_each(nfa_state, ctx->states, nstate)
    {
        vec_for_each(nfa_transition, nstate->trans, trans)
        {
            jrx_ccl* ccl = vec_ccl_get(ctx->ccls->ccls, trans.ccl);
            if ( ! (ccl_is_empty(ccl) || ccl_is_epsilon(ccl)) )
                ccl_group_add(dfa->ccls, ccl);
        }
    }

    // Make them disjunct.
    ccl_group_disambiguate(dfa->ccls);

    // Create the initial state.
    set_dfa_state_elem* initial = set_dfa_state_elem_create(0);
    dfa_state_elem ielem = {nfa->initial->id, 0};
    set_dfa_state_elem_insert(initial, ielem);
    dfa->initial = reserve_dfastate_id(dfa, initial);
    dfa->initial_dstate = initial;

    vec_tag_op* tops = 0;

    if ( nfa->initial_tags ) {
        set_for_each(tag, nfa->initial_tags, tag)
        {
            if ( ! tops )
                tops = vec_tag_op_create(0);

            jrx_tag_op top = {0, 0, tag.reg};
            vec_tag_op_append(tops, top);
        }
    }

    dfa->initial_ops = tops;

    int lazy = (ctx->options & JRX_OPTION_LAZY);
    dfa_state_compute(ctx, dfa, dfa->initial, initial, ! lazy);

    if ( ctx->options & JRX_OPTION_DEBUG )
        dfa_print(dfa, stderr);

    return dfa;
}

void dfa_delete(jrx_dfa* dfa)
{
    if ( dfa->initial_ops )
        vec_tag_op_delete(dfa->initial_ops);

    vec_for_each(dfa_state, dfa->states, dstate)
    {
        if ( dstate )
            _dfa_state_delete(dstate);
    }

    vec_for_each(dfa_state_elem, dfa->state_elems, state_elem)
    {
        if ( state_elem )
            set_dfa_state_elem_delete(state_elem);
    }

    vec_dfa_state_elem_delete(dfa->state_elems);

    vec_dfa_state_delete(dfa->states);
    kh_destroy(dfa_state_elem, dfa->hstates);
    ccl_group_delete(dfa->ccls);

    if ( dfa->initial_dstate )
        set_dfa_state_elem_delete(dfa->initial_dstate);

    free(dfa);
}

jrx_dfa* dfa_compile(const char* pattern, int len, jrx_option options, int8_t nmatch,
                     const char** errmsg)
{
    jrx_nfa* nfa = nfa_compile(pattern, len, options, nmatch, errmsg);
    if ( ! nfa )
        return 0;

    jrx_dfa* dfa = dfa_from_nfa(nfa);
    assert(dfa);

    if ( options & JRX_OPTION_DEBUG )
        dfa_print(dfa, stderr);

    return dfa;
}

static void _vec_tag_op_print(vec_tag_op* tops, FILE* file)
{
    if ( ! tops ) {
        fputs("none", file);
        return;
    }

    int first = 1;
    vec_for_each(tag_op, tops, top)
    {
        if ( ! first )
            fputs(", ", file);
        fprintf(file, "old=%d/new=%d/tag=%d", top.told, top.tnew, top.tag);
        first = 0;
    }
}

static void _dfa_state_print(jrx_dfa* dfa, jrx_dfa_state* dstate, FILE* file)
{
    if ( ! dstate ) {
        fputs("(not computed)", file);
        return;
    }

    if ( dstate->accepts ) {
        fputs(" accepts with", file);
        vec_for_each(dfa_accept, dstate->accepts, acc)
        {
            fprintf(file, " (%d, t%d, final assertions %d, final ops", acc.aid, acc.tid,
                    acc.final_assertions);
            _vec_tag_op_print(acc.final_ops, file);
            fprintf(stderr, ")\n");
        }

        fputs("\n", file);
    }

    vec_for_each(dfa_transition, dstate->trans, trans)
    {
        fputs(" ", file);
        jrx_ccl* ccl = vec_ccl_get(dfa->ccls->ccls, trans.ccl);
        ccl_print(ccl, file);
        fprintf(file, "  -> %d", trans.succ);

        fprintf(file, " (tag ops are ");
        _vec_tag_op_print(trans.tops, file);
        fprintf(file, ")");
        fprintf(file, "\n");
    }
}

void dfa_print(jrx_dfa* dfa, FILE* file)
{
    fprintf(file, "== DFA with %d states\n", vec_dfa_state_size(dfa->states));

    fprintf(file, "options %d\n", dfa->options);
    fprintf(file, "max tag %d\n", dfa->max_tag);
    fprintf(file, "max capture %d\n", dfa->max_capture);

    fprintf(file, "initial tag ops are ");
    _vec_tag_op_print(dfa->initial_ops, file);
    fprintf(file, "\n");

    vec_for_each(dfa_state, dfa->states, dstate)
    {
        fprintf(file, "state %d\n", __jdstate);
        _dfa_state_print(dfa, dstate, file);

        if ( __jdstate == dfa->initial )
            fputs(" -> initial state\n", file);

        fputs("\n", file);
    }

    if ( ! dfa->hstates ) {
        fprintf(file, "(no state sets available)\n");
        return;
    }

    fputs("state sets\n", file);

    khiter_t k;
    for ( k = kh_begin(dfa->hstates); k != kh_end(dfa->hstates); ++k ) {
        if ( ! kh_exist(dfa->hstates, k) )
            continue;

        fputs(" ( ", file);

        set_dfa_state_elem dstate = kh_key(dfa->hstates, k);

        set_for_each(dfa_state_elem, &dstate, delem)
            fprintf(file, "(#%d, t%d) ", delem.nid, delem.tid);

        fputs(")", file);

        fprintf(file, " -> #%d\n", kh_value(dfa->hstates, k));
    }

    fputs("\n", file);

    fputs("CCLs:\n", file);
    ccl_group_print(dfa->ccls, file);
    fputs("\n", file);
}
