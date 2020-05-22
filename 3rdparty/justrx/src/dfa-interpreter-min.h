// $Id$
//
// Minimal matcher interface, for interpreting a compiled DFA without capture
// support. This interface is compatible to functions produced by the JIT
// compilation into LLVM code.

#ifndef JRX_DFA_MIN_MATCHER_H
#define JRX_DFA_MIN_MATCHER_H

#include "dfa.h"
#include "jrx-intern.h"

// >0: Match with the return accept ID (if multiple match, undefined which).
//  0: Failure to match, not recoverable.
// -1: Partial match (e.g., no match yet but might still happen).
// *prev must be NULL initially and not modified between calls.
extern int jrx_match_state_advance_min(jrx_match_state* ms, jrx_char cp, jrx_assertion assertions);

#endif
