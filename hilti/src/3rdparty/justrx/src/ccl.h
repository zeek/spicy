// $Id$
//
// TODO: We should really use better data structures for (a) managing sets of
// intervals within a CCL; and (b) managing set of CCLs.

#ifndef JRX_CCL_H
#define JRX_CCL_H

#include <stdio.h>

#include "jrx-intern.h"
#include "set.h"
#include "vector.h"

// A range of characters.
typedef struct {
    jrx_char begin; // First element of range.
    jrx_char end;   // One after last element of range.
} jrx_char_range;

struct jrx_ccl;

DECLARE_SET(ccl_id, jrx_ccl_id, uint32_t, SET_STD_EQUAL)
DECLARE_VECTOR(ccl, struct jrx_ccl*, jrx_ccl_id)
DECLARE_VECTOR(std_ccl, struct jrx_ccl*, jrx_std_ccl)

// A collection of character classes, managed jointly.
typedef struct {
    vec_ccl* ccls;         // Vector of all CCLs indexed by their ID.
    vec_std_ccl* std_ccls; // Cache for standard CCLs once computed.
} jrx_ccl_group;

static inline int _jrx_cmp_char_ranges(jrx_char_range r1, jrx_char_range r2)
{
    return r1.begin != r2.begin ? SET_STD_EQUAL(r1.begin, r2.begin) : SET_STD_EQUAL(r1.end, r2.end);
}

// A set of character ranges.
DECLARE_SET(char_range, jrx_char_range, uint32_t, _jrx_cmp_char_ranges)

// A character class.
typedef struct jrx_ccl {
    jrx_ccl_id id;            // ID of CCL, unique within CCL group.
    jrx_ccl_group* group;     // The group this CCL is part of.
    jrx_assertion assertions; // Assertions required for CCL to apply.
    set_char_range* ranges;   // Ranges for this CCL; NULL for epsilon transition.
} jrx_ccl;

extern jrx_ccl* ccl_empty(jrx_ccl_group* group);
extern void ccl_print(jrx_ccl* ccl, FILE* file);

// Do not modify any of the CCLs returned directly; use only the functions
// provided here for that.
extern jrx_ccl* ccl_from_range(jrx_ccl_group* group, jrx_char begin, jrx_char end);
extern jrx_ccl* ccl_from_std_ccl(jrx_ccl_group* group, jrx_std_ccl stdl);
extern jrx_ccl* ccl_epsilon(jrx_ccl_group* group);
extern jrx_ccl* ccl_any(jrx_ccl_group* group);

extern jrx_ccl* ccl_negate(jrx_ccl* ccl);
extern jrx_ccl* ccl_add_assertions(jrx_ccl* ccl, jrx_assertion assertions);
extern jrx_ccl* ccl_join(jrx_ccl* ccl1, jrx_ccl* ccl2);

extern int ccl_is_empty(jrx_ccl* ccl);
extern int ccl_is_epsilon(jrx_ccl* ccl);
extern int ccl_do_intersect(jrx_ccl* ccl1, jrx_ccl* ccl2);

extern jrx_ccl_group* ccl_group_create();
extern void ccl_group_delete(jrx_ccl_group* group);
extern void ccl_group_print(jrx_ccl_group* group, FILE* file);
extern jrx_ccl* ccl_group_add(jrx_ccl_group* group, jrx_ccl* ccl);

extern void ccl_group_disambiguate(jrx_ccl_group* group);

#endif
