// $Id$
//
// Matcher interface, for interpreting a compiled DFA.

#ifndef JRX_DFA_MATCHER_H
#define JRX_DFA_MATCHER_H

#include "dfa.h"
#include "jrx-intern.h"

typedef struct {
    jrx_accept_id aid;
    jrx_offset* tags;
} jrx_match_accept;


static inline int _jrx_cmp_match_accept(jrx_match_accept a, jrx_match_accept b)
{
    return a.aid != b.aid ? SET_STD_EQUAL(a.aid, b.aid) :
                            SET_STD_EQUAL(a.tags, b.tags); // ptr comparision ok.
}

DECLARE_SET(match_accept, jrx_match_accept, uint32_t, _jrx_cmp_match_accept)

extern int jrx_match_state_advance(jrx_match_state* ms, jrx_char cp, jrx_assertion assertions);
extern jrx_offset* jrx_match_state_copy_tags(jrx_match_state* ms, jrx_tag_group_id tid);

#endif
