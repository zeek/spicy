// $Id$

#ifndef JRX_DFA_H
#define JRX_DFA_H

#include "jrx-intern.h"
#include "khash.h"
#include "nfa.h"
#include "set.h"

typedef uint16_t jrx_jrx_tag_group_id;

typedef struct {
    jrx_nfa_state_id nid;     // The NFA state.
    jrx_jrx_tag_group_id tid; // The tag group we're storing tags in.
} dfa_state_elem;

static inline int _jrx_cmp_dfa_state_elem(dfa_state_elem a, dfa_state_elem b)
{
    return a.nid != b.nid ? SET_STD_EQUAL(a.nid, b.nid) : SET_STD_EQUAL(a.tid, b.tid);
}

DECLARE_SET(dfa_state_elem, dfa_state_elem, uint32_t, _jrx_cmp_dfa_state_elem)

static inline khint_t _jrx_hash_dfa_state_elem(set_dfa_state_elem dstate)
{
    khint_t hash = set_dfa_state_elem_size(&dstate);
    set_for_each(dfa_state_elem, &dstate, delem) hash =
        (((hash << 4) ^ (hash >> 28)) + (delem.nid + delem.tid));

    return hash;
}

static inline khint_t _jrx_eq_set_dfa_state_elem(set_dfa_state_elem a, set_dfa_state_elem b)
{
    return set_dfa_state_elem_equal(&a, &b);
}

KHASH_INIT(dfa_state_elem, set_dfa_state_elem, jrx_dfa_state_id, 1, _jrx_hash_dfa_state_elem,
           _jrx_eq_set_dfa_state_elem)
typedef khash_t(dfa_state_elem) hash_dfa_state;

typedef uint8_t jrx_tag_group_id;

typedef struct {
    jrx_tag_group_id told;
    jrx_tag_group_id tnew;
    int8_t tag;
} jrx_tag_op;

DECLARE_VECTOR(tag_op, jrx_tag_op, uint32_t)

typedef struct {
    jrx_ccl_id ccl;
    jrx_dfa_state_id succ;
    vec_tag_op* tops;
} jrx_dfa_transition;

DECLARE_VECTOR(dfa_transition, jrx_dfa_transition, uint32_t)

typedef struct {
    jrx_assertion final_assertions; // Final assertions required for accepting.
    jrx_accept_id aid;              // The ID to accept with.
    jrx_tag_group_id tid;           // The tag group to use.
    vec_tag_op* final_ops;          // Final tag operations when accepting.
    jrx_offset* tags;               // A copy of the final tag values.
} jrx_dfa_accept;

DECLARE_VECTOR(dfa_accept, jrx_dfa_accept, uint32_t)

typedef struct {
    vec_dfa_accept* accepts;   // Accepts for this state.
    vec_dfa_transition* trans; // Transitions out of this state.
} jrx_dfa_state;

DECLARE_VECTOR(dfa_state, jrx_dfa_state*, jrx_dfa_state_id)
DECLARE_VECTOR(dfa_state_elem, set_dfa_state_elem*, jrx_dfa_state_id)

typedef struct jrx_dfa {
    jrx_option options;                 // Options specified for compilation.
    int8_t nmatch;                      // Max. number of captures the user is interested in.
    int8_t max_tag;                     // Largest tag number used.
    int8_t max_capture;                 // Largest capture group number used.
    jrx_dfa_state_id initial;           // Initial state.
    set_dfa_state_elem* initial_dstate; // Initial state.
    vec_tag_op* initial_ops;            // Initial tag operations.
    vec_dfa_state* states;              // Array of DFA states, indexed by their ID.
    vec_dfa_state_elem* state_elems;    // Array of states, indexed by their ID.
    hash_dfa_state* hstates;            // Hash of states indexed by set of NFA states.
    jrx_ccl_group* ccls;                // CCLs for the DFA.
    jrx_nfa* nfa;                       // The underlying NFA.
} jrx_dfa;


extern jrx_dfa* dfa_compile(const char* pattern, int len, jrx_option options, int8_t nmatch,
                            const char** errmsg);
extern jrx_dfa* dfa_from_nfa(jrx_nfa* nfa);
extern int dfa_state_compute(jrx_nfa_context* ctx, jrx_dfa* dfa, jrx_dfa_state_id id,
                             set_dfa_state_elem* dstate, int recurse);
extern jrx_dfa_state* dfa_get_state(jrx_dfa* dfa, jrx_dfa_state_id id);
extern void dfa_delete(jrx_dfa* dfa);
extern void dfa_print(jrx_dfa* dfa, FILE* file);

#endif
