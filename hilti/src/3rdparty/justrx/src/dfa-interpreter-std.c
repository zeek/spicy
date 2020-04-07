// $Id$

#include "dfa-interpreter-std.h"
#include "jlocale.h"
#include "jrx-intern.h"
#include "nfa.h"

static int _ccl_match_assertions(jrx_char cp, jrx_char* previous, jrx_assertion have,
                                 jrx_assertion want)
{
    if ( want & JRX_ASSERTION_WORD_BOUNDARY )
        have |= local_word_boundary(previous, cp) ? JRX_ASSERTION_WORD_BOUNDARY : 0;

    if ( want & JRX_ASSERTION_NOT_WORD_BOUNDARY )
        have |= local_word_boundary(previous, cp) ? 0 : JRX_ASSERTION_NOT_WORD_BOUNDARY;

    return (want & have) == want;
}

static int _ccl_match(jrx_ccl* ccl, jrx_char cp, jrx_char* previous, jrx_assertion assertions)
{
    if ( ! ccl->ranges )
        return 0;

    if ( ! _ccl_match_assertions(cp, previous, assertions, ccl->assertions) )
        return 0;

    // Look at ranges.
    set_for_each(char_range, ccl->ranges, r)
    {
        if ( cp >= r.begin && cp < r.end )
            return 1;
    }

    return 0;
}

static inline size_t _tag_group_size(jrx_match_state* ms)
{
    return (ms->dfa->max_tag + 1) * sizeof(jrx_offset);
}

static inline void* _resize_tags(jrx_match_state* ms, jrx_offset* tags, int* size,
                                 jrx_tag_group_id group)
{
    int old_size = *size * _tag_group_size(ms);
    int new_size = (group + 1) * _tag_group_size(ms);

    char* t = realloc(tags, new_size);
    memset(t + old_size, 0, new_size - old_size);

    *size = (group + 1);
    return t;
}

static inline jrx_offset* _tag_group(jrx_match_state* ms, int tags, jrx_tag_group_id group)
{
    jrx_offset* buffer;

    if ( tags ) {
        if ( group >= ms->tags1_size )
            ms->tags1 = _resize_tags(ms, ms->tags1, &ms->tags1_size, group);

        buffer = ms->tags1;
    }

    else {
        if ( group >= ms->tags2_size )
            ms->tags2 = _resize_tags(ms, ms->tags2, &ms->tags2_size, group);

        buffer = ms->tags2;
    }

    return (jrx_offset*)(((char*)buffer) + (group * _tag_group_size(ms)));
}

static void _update_tags(jrx_match_state* ms, vec_tag_op* tops)
{
    if ( ! tops )
        return;

    int oldct = ms->current_tags;
    int newct = 1 - oldct;

    // We first copy each old group to the new place.
    vec_for_each(tag_op, tops, top) memcpy(_tag_group(ms, newct, top.tnew),
                                           _tag_group(ms, oldct, top.told), _tag_group_size(ms));

    // Now apply operations.
    vec_for_each(tag_op, tops, top2)
    {
        if ( top2.tag < 0 )
            continue;

        jrx_offset* group = _tag_group(ms, newct, top2.tnew);
        group[top2.tag] = ms->offset;
    }

    ms->current_tags = newct;
}

static void _update_accepts(jrx_match_state* ms, jrx_dfa_state* state, jrx_char cp,
                            jrx_assertion assertions)
{
    if ( ! state->accepts )
        return;

    vec_for_each(dfa_accept, state->accepts, acc)
    {
        if ( ! _ccl_match_assertions(cp, (ms->offset ? &ms->previous : 0), assertions,
                                     acc.final_assertions) )
            // No match, final assertions don't work out.
            continue;

        if ( ms->dfa->options & JRX_OPTION_NO_CAPTURE ) {
            jrx_match_accept nacc = {acc.aid, 0};
            set_match_accept_insert(ms->accepts, nacc);
            return;
        }

        jrx_offset* tags = jrx_match_state_copy_tags(ms, acc.tid);

        if ( acc.final_ops ) {
            vec_for_each(tag_op, acc.final_ops, op)
            {
                tags[op.tag] = ms->offset;
            }
        }

        jrx_match_accept nacc = {acc.aid, tags};

        // If we already have an entry with that acc.aid, we only keep the
        // one with the left-most longest match.

        int found_old = 0;
        set_for_each(match_accept, ms->accepts, oacc)
        {
            if ( nacc.aid != oacc.aid )
                continue;

            found_old = 1;

            int olen = oacc.tags[0] > 0 && oacc.tags[1] > 0 ? oacc.tags[1] - oacc.tags[0] : -1;
            int nlen = nacc.tags[0] > 0 && nacc.tags[1] > 0 ? nacc.tags[1] - nacc.tags[0] : -1;

            if ( nlen < 0 )
                goto keep_old;

            if ( olen < 0 )
                goto keep_new;

            if ( oacc.tags[0] < nacc.tags[0] )
                // Left-most.
                goto keep_old;

            if ( oacc.tags[0] == nacc.tags[0] && nlen > olen )
                // Longest if same start position.
                goto keep_new;

        keep_old:
            free(nacc.tags);
            break;

        keep_new:
            if ( oacc.tags )
                free(oacc.tags);

            set_match_accept_remove(ms->accepts, oacc);
            set_match_accept_insert(ms->accepts, nacc);
            break;
        }

        if ( ! found_old )
            set_match_accept_insert(ms->accepts, nacc);
    }
}

jrx_match_state* jrx_match_state_init(const jrx_regex_t* preg, jrx_offset begin,
                                      jrx_match_state* ms)
{
    jrx_dfa* dfa = preg->dfa;

    ms->offset = 1;
    ms->begin = begin;
    ms->previous = 0;
    ms->dfa = dfa;
    ms->state = dfa->initial;
    ms->current_tags = 0;
    ms->acc = -1;
    ms->tags1 = 0;
    ms->tags2 = 0;
    ms->tags1_size = 0;
    ms->tags2_size = 0;
    ms->cflags = preg->cflags;

    if ( (dfa->options & JRX_OPTION_STD_MATCHER) ) {
        ms->accepts = set_match_accept_create(0);

        _update_tags(ms, dfa->initial_ops);
        jrx_dfa_state* state = dfa_get_state(ms->dfa, ms->state);
        _update_accepts(ms, state, 0, JRX_ASSERTION_BOL | JRX_ASSERTION_BOD);
    }
    else {
        ms->accepts = 0;
        ms->current_tags = -1;
    }

    return ms;
}

void jrx_match_state_done(jrx_match_state* ms)
{
    if ( ms->dfa->options & JRX_OPTION_NO_CAPTURE )
        return;

    set_for_each(match_accept, ms->accepts, acc)
    {
        if ( acc.tags )
            free(acc.tags);
    }

    set_match_accept_delete(ms->accepts);

    free(ms->tags1);
    free(ms->tags2);
}

static void print_accept_set(set_match_accept* s)
{
    fputs(" (accept set is [", stderr);

    int first = 1;
    set_for_each(match_accept, s, acc)
    {
        if ( ! first )
            fputc(',', stderr);
        fprintf(stderr, "(%d, 0x%p)", acc.aid, acc.tags);
        first = 0;
    }

    fputs("])\n", stderr);
}

int jrx_match_state_advance(jrx_match_state* ms, jrx_char cp, jrx_assertion assertions)
{
    jrx_dfa_state* state = dfa_get_state(ms->dfa, ms->state);

    if ( ! state )
        return 0;

    if ( ms->dfa->options & JRX_OPTION_DEBUG )
        fprintf(stderr, "> in state #%d at offset %d with input symbol %d and assertions %d ",
                ms->state, ms->offset, cp, assertions);

    vec_for_each(dfa_transition, state->trans, trans)
    {
        jrx_ccl* ccl = vec_ccl_get(ms->dfa->ccls->ccls, trans.ccl);

        if ( ! _ccl_match(ccl, cp, ms->offset ? &ms->previous : 0, assertions) )
            // Doesn't match.
            continue;

        // Found transition.
        jrx_dfa_state_id succ_id = trans.succ;
        jrx_dfa_state* succ_state = dfa_get_state(ms->dfa, succ_id);
        vec_tag_op* tops = trans.tops;

        ms->state = succ_id;
        ms->previous = cp;

        _update_tags(ms, tops);

        ++ms->offset;

        _update_accepts(ms, succ_state, cp, assertions);

        if ( ms->dfa->options & JRX_OPTION_DEBUG ) {
            fprintf(stderr, "-> found transition, new state is #%d", ms->state);
            print_accept_set(ms->accepts);
        }

        return 1;
    }

    if ( ms->dfa->options & JRX_OPTION_DEBUG ) {
        fprintf(stderr, "-> no transition possible");
        print_accept_set(ms->accepts);
    }

    return 0;
}

jrx_offset* jrx_match_state_copy_tags(jrx_match_state* ms, jrx_tag_group_id tid)
{
    jrx_offset* tags = (jrx_offset*)malloc(_tag_group_size(ms));
    jrx_offset* group = _tag_group(ms, ms->current_tags, tid);
    memcpy(tags, group, _tag_group_size(ms));

    assert(ms->current_tags ? ms->tags1 : ms->tags2);

    return tags;
}
