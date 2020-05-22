
// If we are compiled as part of HILTI, use it's memory management functions.

#ifndef JRX_MEMMGT_H
#define JRX_MEMMGT_H

#ifdef JRX_USE_HILTI

#include "memory_.h"

#define malloc hlt_malloc
#define calloc hlt_calloc
#define realloc hlt_realloc_no_init
#define free hlt_free

#endif

#endif
