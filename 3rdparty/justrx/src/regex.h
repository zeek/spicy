// $Id$
//
// regcomp/regexec compatible interface, as far as our capabilities allow.

#ifndef JRX_REGEX_H
#define JRX_REGEX_H

#include "jrx.h"

#define regcomp jrx_regcomp
#define regerror jrx_regerror
#define regexec jrx_regexec
#define regfree jrx_regfree
#define regex_t jrx_regex_t
#define regmatch_t jrx_regmatch_t

#endif
