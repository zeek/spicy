// $Id$

/// \addtogroup NFA
///
/// Functions for manipulating NFAs.

#ifndef JRX_NFA_H
#define JRX_NFA_H

#include "ccl.h"
#include "jrx-intern.h"

/** \addtogroup NFA */
// @{

/// Defines a tag by register ID and priority. Tags can be attached to
/// transitions and will then during matching assign the current input
/// position to the tag's register. If multiple transitions reach the same
/// destination state simultaneously while attempting to set different
/// registers, the tag with highest priority will win.
typedef struct {
    int8_t reg;  ///< Tag's register.
    int8_t prio; ///< Tag's Priority. Default is zero, and larger priority is more important.
} jrx_tag;

/// A set of ~~nfa_state_id.
DECLARE_SET(nfa_state_id, jrx_nfa_state_id, jrx_nfa_state_id, SET_STD_EQUAL)

static inline int _jrx_cmp_tag(jrx_tag t1, jrx_tag t2)
{
    return t1.reg != t2.reg ? SET_STD_EQUAL(t1.reg, t2.reg) : SET_STD_EQUAL(t1.prio, t2.prio);
}

/// A ~~set of ~~jrx_tag.
DECLARE_SET(tag, jrx_tag, uint32_t, _jrx_cmp_tag)

struct jrx_nfa_state;

/// A ~~vector of ~~jrx_nfa_state pointers.
DECLARE_VECTOR(nfa_state, struct jrx_nfa_state*, jrx_nfa_state_id)

/// Groups a set of related NFAs together. NFA which are manipulated jointly
/// (e.g., by building a new NFA out of a set of others) must be part of the
/// same context. Each NFA only exists as long as the context is valid which
/// it is part of.
typedef struct {
    jrx_option options;       // Options applying to all NFAs.
    int8_t nmatch;            // Max. number of captures the user is interested in.
    int8_t max_tag;           // Largest tag number used.
    int8_t max_capture;       // Largest capture group number used.
    jrx_accept_id max_accept; // Highest accept ID assigned so far.
    jrx_ccl_group* ccls;      // All CCLs.
    vec_nfa_state* states;    // Vector of states indexed by their ID.
    int refcnt;               // Reference counter for memory management.
} jrx_nfa_context;


/// A transition between two NFA states.
typedef struct {
    jrx_ccl_id ccl;        // CCL for transition.
    jrx_nfa_state_id succ; // Successor state.
    set_tag* tags;         // Tags to apply on transition.
} jrx_nfa_transition;

/// Attached to an NFA state to signal acceptance.
typedef struct {
    jrx_assertion assertions; // Final assertions needed for acceptance.
    jrx_accept_id aid;        // Accept with this ID.
    set_tag* tags;            // Final tags to apply when accepting.
} jrx_nfa_accept;

/// A vector of ~~nfa_accept.
DECLARE_VECTOR(nfa_accept, jrx_nfa_accept, uint32_t)

/// A vector of ~~nfa_transition.
DECLARE_VECTOR(nfa_transition, jrx_nfa_transition, uint32_t)

/// An individual NFA state.
typedef struct jrx_nfa_state {
    jrx_nfa_state_id id;       // Unique ID for this state.
    vec_nfa_accept* accepts;   // Accept with these, or 0 if none.
    vec_nfa_transition* trans; // Pointer to transition array.
} jrx_nfa_state;

/// An NFA. Each NFA is associated with an ~~jrx_nfa_context.
typedef struct jrx_nfa {
    jrx_nfa_context* ctx;   // The context the NFA is part of.
    set_tag* initial_tags;  // The "incoming" tags.
    jrx_nfa_state* initial; // The initial state.
    jrx_nfa_state* final;   // The final state.
} jrx_nfa;

/// Creates a new NFA context.
///
/// \param options Options applying to all NFAs associated with this context.
///
/// \param nmatch The maximum number of capture groups one is interested in for any
/// NFA associated with this context; -1 if access to *all* groups is desired.
extern jrx_nfa_context* nfa_context_create(jrx_option options, int8_t nmatch);


/// Delete an NFA context.
///
/// \param ctx The context to delete. The instance it points must not be
/// accessed anymore after the call.
extern void nfa_context_delete(jrx_nfa_context* ctx);

/// Creates a new NFA state.
///
/// \param ctx The context the NFA is to be associated with.
/// \param initial The initial state of the NFA.
/// \param final The final state of the NFA.
///
/// Note: The *final* state will be used for link this NFA with others, like
/// with ~~nfa_concat. We assume there's only a single state representing the
/// "exit" position. The final state does not need to be an accepting state.
extern jrx_nfa* nfa_create(jrx_nfa_context* ctx, jrx_nfa_state* initial, jrx_nfa_state* final);

/// Delete an NFA.
///
/// \param nfa The NFA to delete. The instance it points must not be accessed
/// anymore after the call.
extern void nfa_delete(jrx_nfa* nfa);

extern jrx_nfa* nfa_set_accept(jrx_nfa* nfa, jrx_accept_id accept);
extern jrx_nfa* nfa_set_capture(jrx_nfa* nfa, uint8_t group);

extern jrx_nfa* nfa_empty(jrx_nfa_context* ctx);
extern jrx_nfa* nfa_from_ccl(jrx_nfa_context* ctx, jrx_ccl* ccl);
extern jrx_nfa* nfa_concat(jrx_nfa* nfa1, jrx_nfa* nfa2, jrx_ccl* ccl);
extern jrx_nfa* nfa_alternative(jrx_nfa* nfa1, jrx_nfa* nfa2);
extern jrx_nfa* nfa_iterate(jrx_nfa* nfa, int min, int max);

extern void nfa_remove_epsilons(jrx_nfa* nfa);

// Compile a single pattern.
extern jrx_nfa* nfa_compile(const char* pattern, int len, jrx_option options, int8_t nmatch,
                            const char** errmsg);

// Add another pattern alternative to an existing NFA.
extern jrx_nfa* nfa_compile_add(jrx_nfa* nfa, const char* pattern, int len, const char** errmsg);

extern void nfa_state_print(jrx_nfa_context* ctx, jrx_nfa_state* state, FILE* file);
extern void nfa_print(jrx_nfa* nfa, FILE* file);

//@}

#endif
