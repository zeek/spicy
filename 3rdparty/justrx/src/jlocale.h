// $Id$
//
// Function implementing local- and encoding-specific functionality.
//
// TODO: Currently, these are just hard-coded in local-independent,
// ASCII-only way.

#ifndef JRX_JITTYPE_H
#define JRX_JITTYPE_H

#include <ctype.h>

#include "ccl.h"
#include "jrx-intern.h"

extern jrx_ccl* local_ccl_lower(jrx_ccl_group* group);
extern jrx_ccl* local_ccl_upper(jrx_ccl_group* group);
extern jrx_ccl* local_ccl_word(jrx_ccl_group* group);
extern jrx_ccl* local_ccl_digit(jrx_ccl_group* group);
extern jrx_ccl* local_ccl_blank(jrx_ccl_group* group);

static inline int _isword(jrx_char cp)
{
    return isalnum(cp) || cp == '_';
}

static inline int local_word_boundary(jrx_char* prev, jrx_char current)
{
    return _isword(current) ? (prev ? ! _isword(*prev) : 1) : 0;
}

#endif
