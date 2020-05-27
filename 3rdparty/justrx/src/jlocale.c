// $Id$

#include "jlocale.h"
#include "jrx-intern.h"

static inline jrx_ccl* _add_range(jrx_ccl* ccl, jrx_char min, jrx_char max)
{
    jrx_ccl* nccl = ccl_from_range(ccl->group, min, max + 1);
    return ccl_join(ccl, nccl);
}

jrx_ccl* local_ccl_lower(jrx_ccl_group* group)
{
    jrx_ccl* ccl = ccl_empty(group);
    ccl = _add_range(ccl, 'a', 'z');
    return ccl;
}

jrx_ccl* local_ccl_upper(jrx_ccl_group* group)
{
    jrx_ccl* ccl = ccl_empty(group);
    ccl = _add_range(ccl, 'A', 'Z');
    return ccl;
}

jrx_ccl* local_ccl_word(jrx_ccl_group* group)
{
    jrx_ccl* ccl = ccl_empty(group);
    ccl = _add_range(ccl, 'a', 'z');
    ccl = _add_range(ccl, 'A', 'Z');
    ccl = _add_range(ccl, '0', '9');
    ccl = _add_range(ccl, '_', '_');
    return ccl;
}

jrx_ccl* local_ccl_digit(jrx_ccl_group* group)
{
    jrx_ccl* ccl = ccl_empty(group);
    ccl = _add_range(ccl, '0', '9');
    return ccl;
}

jrx_ccl* local_ccl_blank(jrx_ccl_group* group)
{
    jrx_ccl* ccl = ccl_empty(group);
    ccl = _add_range(ccl, ' ', ' ');
    ccl = _add_range(ccl, '\t', '\t');
    return ccl;
}
