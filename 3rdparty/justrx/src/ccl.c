// $Id$

#include "ccl.h"
#include "jlocale.h"
#include "jrx-intern.h"
#include "util.h"

#include <stdlib.h>
#include <string.h>

static jrx_ccl* _ccl_create_epsilon()
{
    jrx_ccl* ccl = (jrx_ccl*)malloc(sizeof(jrx_ccl));
    ccl->id = 0;
    ccl->group = 0;
    ccl->assertions = 0;
    ccl->ranges = 0;
    return ccl;
}

static jrx_ccl* _ccl_create_empty()
{
    jrx_ccl* ccl = _ccl_create_epsilon();
    ccl->ranges = set_char_range_create(0);
    return ccl;
}

// Not exposed; delete whole CCL group instead.
static void _ccl_delete(jrx_ccl* ccl)
{
    if ( ccl->group ) {
        vec_ccl_set(ccl->group->ccls, ccl->id, 0);
        ccl->group = 0;
    }

    if ( ccl->ranges )
        set_char_range_delete(ccl->ranges);

    free(ccl);
}

static int _ccl_is_part_of(jrx_ccl* ccl1, jrx_ccl* ccl2)
{
    if ( ccl1->assertions != ccl2->assertions )
        return 0;

    if ( ! ccl1->ranges )
        return 1;

    if ( ! ccl2->ranges )
        return 0;

    set_for_each(char_range, ccl1->ranges, r1)
    {
        int found = 0;
        set_for_each(char_range, ccl2->ranges, r2)
        {
            if ( r1.begin >= r2.begin && r1.end <= r2.end )
                found = 1;
        }

        if ( ! found )
            return 0;
    }

    return 1;
}

static int _ccl_compare(jrx_ccl* ccl1, jrx_ccl* ccl2)
{
    if ( ccl1->assertions != ccl2->assertions )
        return 0;

    int p1 = _ccl_is_part_of(ccl1, ccl2);
    int p2 = _ccl_is_part_of(ccl2, ccl1);

    return p1 && p2;
}

static jrx_ccl* _ccl_group_find(jrx_ccl_group* group, jrx_ccl* ccl)
{
    vec_for_each(ccl, group->ccls, gccl)
    {
        if ( gccl && _ccl_compare(ccl, gccl) )
            return gccl;
    }

    return 0;
}

static jrx_ccl* _ccl_group_add_to(jrx_ccl_group* group, jrx_ccl* ccl)
{
    jrx_ccl* existing = _ccl_group_find(group, ccl);
    if ( existing ) {
        if ( existing != ccl )
            _ccl_delete(ccl);

        assert(existing->group == group);
        return existing;
    }

    ccl->group = group;
    ccl->id = vec_ccl_size(group->ccls);
    vec_ccl_set(group->ccls, ccl->id, ccl);
    return ccl;
}

static jrx_ccl* _ccl_copy(jrx_ccl* ccl)
{
    jrx_ccl* copy = _ccl_create_epsilon();
    copy->assertions = ccl->assertions;
    copy->ranges = ccl->ranges ? set_char_range_copy(ccl->ranges) : 0;
    return copy;
}

// Deletes empty ranges from CCL.
static void _ccl_cleanup(jrx_ccl* ccl)
{
    if ( ! ccl->ranges )
        return;

    set_char_range* nranges = set_char_range_create(0);

    // Keep only non-empty intervals.
    set_for_each(char_range, ccl->ranges, r)
    {
        if ( r.begin < r.end )
            set_char_range_insert(nranges, r);
    }

    set_char_range_delete(ccl->ranges);
    ccl->ranges = nranges;
}

static void _ccl_subtract_range(jrx_ccl* ccl, jrx_char_range sub)
{
    if ( ! ccl->ranges )
        return;

    set_char_range* addlranges = set_char_range_create(0);

    set_for_each(char_range, ccl->ranges, r)
    {
        if ( sub.begin >= r.begin && sub.begin <= r.end ) {
            if ( sub.end >= r.begin && sub.end <= r.end ) {
                // Need to split range.
                jrx_char_range nr1 = {r.begin, sub.begin};
                set_char_range_insert(addlranges, nr1);

                jrx_char_range nr2 = {sub.end, r.end};
                set_char_range_insert(addlranges, nr2);
            }

            else {
                // Adjust right end.
                jrx_char_range nr = {r.begin, sub.begin};
                set_char_range_insert(addlranges, nr);
            }
        }

        else if ( sub.end >= r.begin && sub.end <= r.end ) {
            // Adjust left end.
            jrx_char_range nr = {sub.end, r.end};
            set_char_range_insert(addlranges, nr);
        }

        else if ( sub.begin <= r.begin && sub.end >= r.end ) {
            jrx_char_range nr = {r.begin, r.begin};
            set_char_range_insert(addlranges, nr);
        }
        else
            set_char_range_insert(addlranges, r);
    }

    set_char_range_delete(ccl->ranges);
    ccl->ranges = addlranges;
}

static void _ccl_subtract(jrx_ccl* ccl1, jrx_ccl* ccl2)
{
    if ( ! ccl2->ranges )
        return;

    if ( ccl1->assertions != ccl2->assertions )
        return;

    set_for_each(char_range, ccl2->ranges, r) _ccl_subtract_range(ccl1, r);

    _ccl_cleanup(ccl1);
}

static jrx_ccl* _ccl_intersect(jrx_ccl* ccl1, jrx_ccl* ccl2)
{
    if ( ! (ccl1->ranges && ccl2->ranges) )
        return 0;

    if ( ccl1->assertions != ccl2->assertions )
        return 0;

    set_char_range* nranges = set_char_range_create(0);

    set_for_each(char_range, ccl1->ranges, r1)
    {
        set_for_each(char_range, ccl2->ranges, r2)
        {
            if ( r2.begin >= r1.begin && r2.begin <= r1.end ) {
                jrx_char_range nr = {r2.begin, (r1.end < r2.end ? r1.end : r2.end)};
                set_char_range_insert(nranges, nr);
            }

            else if ( r2.end >= r1.begin && r2.end <= r1.end ) {
                jrx_char_range nr = {r1.begin, r2.end};
                set_char_range_insert(nranges, nr);
            }

            else if ( r1.begin >= r2.begin && r1.begin <= r2.end ) {
                jrx_char_range nr = {r1.begin, (r2.end < r1.end ? r2.end : r1.end)};
                set_char_range_insert(nranges, nr);
            }

            else if ( r1.end >= r2.begin && r1.end <= r2.end ) {
                jrx_char_range nr = {r2.begin, r1.end};
                set_char_range_insert(nranges, nr);
            }
        }
    }

    jrx_ccl* nccl = _ccl_create_epsilon();
    nccl->ranges = nranges;
    nccl->assertions = ccl1->assertions;

    _ccl_cleanup(nccl);

    if ( ! ccl_is_empty(nccl) )
        return nccl;


        _ccl_delete(nccl);
        return 0;

}

jrx_ccl_group* ccl_group_create()
{
    jrx_ccl_group* group = (jrx_ccl_group*)malloc(sizeof(jrx_ccl_group));
    group->std_ccls = vec_std_ccl_create(0);
    group->ccls = vec_ccl_create(0);
    return group;
}

void ccl_group_delete(jrx_ccl_group* group)
{
    vec_for_each(ccl, group->ccls, ccl)
    {
        if ( ccl )
            _ccl_delete(ccl);
    }

    vec_ccl_delete(group->ccls);
    vec_std_ccl_delete(group->std_ccls);

    free(group);
}

void ccl_group_print(jrx_ccl_group* group, FILE* file)
{
    vec_for_each(ccl, group->ccls, ccl)
    {
        fputs("  ", file);
        if ( ccl )
            ccl_print(ccl, file);
        fputc('\n', file);
    }
}

jrx_ccl* ccl_empty(jrx_ccl_group* group)
{
    jrx_ccl* ccl = _ccl_create_empty();
    return _ccl_group_add_to(group, ccl);
}

jrx_ccl* ccl_from_range(jrx_ccl_group* group, jrx_char begin, jrx_char end)
{
    jrx_ccl* ccl = _ccl_create_empty();
    jrx_char_range r = {begin, end};
    set_char_range_insert(ccl->ranges, r);
    return _ccl_group_add_to(group, ccl);
}

jrx_ccl* ccl_from_std_ccl(jrx_ccl_group* group, jrx_std_ccl std)
{
    jrx_ccl* ccl = vec_std_ccl_get(group->std_ccls, std);

    if ( ccl )
        return ccl;

    switch ( std ) {
    case JRX_STD_CCL_EPSILON:
        ccl = _ccl_create_epsilon();
        break;

    case JRX_STD_CCL_ANY:
        ccl = ccl_from_range(group, 0, JRX_CHAR_MAX);
        break;

    case JRX_STD_CCL_LOWER:
        ccl = local_ccl_lower(group);
        break;

    case JRX_STD_CCL_UPPER:
        ccl = local_ccl_upper(group);
        break;

    case JRX_STD_CCL_WORD:
        ccl = local_ccl_word(group);
        break;

    case JRX_STD_CCL_DIGIT:
        ccl = local_ccl_digit(group);
        break;

    case JRX_STD_CCL_BLANK:
        ccl = local_ccl_blank(group);
        break;

    case JRX_STD_CCL_NONE:
        jrx_internal_error("ccl_from_std_ccl: JRX_STD_CCL_NONE given");

    default:
        jrx_internal_error("ccl_from_std_ccl: unknown std_ccl type");
    }

    assert(ccl);

    ccl = _ccl_group_add_to(group, ccl);
    vec_std_ccl_set(group->std_ccls, std, ccl);
    return ccl;
}

extern jrx_ccl* ccl_any(jrx_ccl_group* group)
{
    return ccl_from_std_ccl(group, JRX_STD_CCL_ANY);
}

extern jrx_ccl* ccl_epsilon(jrx_ccl_group* group)
{
    return ccl_from_std_ccl(group, JRX_STD_CCL_EPSILON);
}

jrx_ccl* ccl_negate(jrx_ccl* ccl)
{
    assert(! ccl_is_epsilon(ccl));

    jrx_ccl* copy = _ccl_create_empty();
    copy->assertions = ccl->assertions;

    if ( (! ccl->ranges) || set_char_range_size(ccl->ranges) == 0 ) {
        // FIXME: technically, this should be RE_CHAR_MAX + 1...
        jrx_char_range r = {0, JRX_CHAR_MAX};
        set_char_range_insert(copy->ranges, r);
        return _ccl_group_add_to(ccl->group, ccl);
    }

    jrx_char last = 0;

    set_for_each(char_range, ccl->ranges, r)
    {
        jrx_char_range nr = {last, r.begin};
        set_char_range_insert(copy->ranges, nr);
        last = r.end;
    }

    jrx_char_range final = {last, JRX_CHAR_MAX};
    set_char_range_insert(copy->ranges, final);

    _ccl_cleanup(copy);

    return _ccl_group_add_to(ccl->group, copy);
}

jrx_ccl* ccl_add_assertions(jrx_ccl* ccl, jrx_assertion assertions)
{
    jrx_ccl* copy = _ccl_copy(ccl);
    copy->assertions |= assertions;
    return _ccl_group_add_to(ccl->group, copy);
}

jrx_ccl* ccl_join(jrx_ccl* ccl1, jrx_ccl* ccl2)
{
    assert(ccl1->group == ccl2->group);
    assert(ccl1->assertions == ccl2->assertions);

    // FIXME: we don't treat non-disjunct ranges correctly.

    jrx_ccl* ccl = _ccl_create_empty();
    if ( ccl1->ranges )
        set_char_range_join(ccl->ranges, ccl1->ranges);

    if ( ccl2->ranges )
        set_char_range_join(ccl->ranges, ccl2->ranges);

    return _ccl_group_add_to(ccl1->group, ccl);
}

int ccl_is_empty(jrx_ccl* ccl)
{
    if ( ! ccl )
        return 1;

    return (! ccl->ranges) || set_char_range_size(ccl->ranges) == 0;
}

int ccl_is_epsilon(jrx_ccl* ccl)
{
    if ( ! ccl )
        return 1;

    return ! ccl->ranges;
}

jrx_ccl* ccl_group_add(jrx_ccl_group* group, jrx_ccl* ccl)
{
    return _ccl_group_add_to(group, _ccl_copy(ccl));
}

void ccl_group_disambiguate(jrx_ccl_group* group)
{
    int changed;

    do {
        changed = 0;

        jrx_ccl_id i;
        jrx_ccl_id j;
        for ( i = 0; i < vec_ccl_size(group->ccls); i++ )
            for ( j = i + 1; j < vec_ccl_size(group->ccls); j++ ) {
                jrx_ccl* ccl1 = vec_ccl_get(group->ccls, i);
                jrx_ccl* ccl2 = vec_ccl_get(group->ccls, j);

                if ( ccl_is_epsilon(ccl1) || ccl_is_epsilon(ccl2) )
                    continue;

                if ( ccl_is_empty(ccl1) || ccl_is_empty(ccl2) )
                    continue;

                jrx_ccl* intersect = _ccl_intersect(ccl1, ccl2);
                if ( ! intersect )
                    continue;

                jrx_ccl* tmp_ccl1 = _ccl_copy(ccl1);
                _ccl_subtract(ccl1, ccl2);
                _ccl_subtract(ccl2, tmp_ccl1);
                _ccl_delete(tmp_ccl1);

                _ccl_group_add_to(group, intersect);

                changed = 1;
            }

    } while ( changed );
}

int ccl_do_intersect(jrx_ccl* ccl1, jrx_ccl* ccl2)
{
    if ( ! ccl1->ranges && ! ccl2->ranges )
        return 1;

    jrx_ccl* is = _ccl_intersect(ccl1, ccl2);
    if ( is )
        _ccl_delete(is);

    return is != 0;
}

void ccl_print(jrx_ccl* ccl, FILE* file)
{
    assert(ccl);

    fprintf(file, "#%d[", ccl->id);

    if ( ! ccl->ranges )
        fprintf(file, "Epsilon");
    else {
        set_for_each(char_range, ccl->ranges, r)
        {
            fprintf(file, "(%d-", r.begin);
            if ( r.end < JRX_CHAR_MAX )
                fprintf(file, "%d)", r.end);
            else
                fprintf(file, "max)");
        }
    }
    fputc(']', file);

    fprintf(file, " (assertions %d)", ccl->assertions);
}
