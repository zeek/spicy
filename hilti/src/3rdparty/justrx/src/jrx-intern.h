// $Id$
//
// Every file part the library should include this header first so that GC
// can be set up correctly, if necessary.

#ifndef JRX_INTERN_H
#define JRX_INTERN_H

#include "jrx.h"
#include "mem-mgt.h"

#include <stdint.h>

// Predefined constants.
static const jrx_char JRX_CHAR_MAX = UINT32_MAX;    // Max. codepoint.
static const jrx_offset JRX_OFFSET_MAX = INT32_MAX; // Max. offset value.

// Matching options.
typedef uint8_t jrx_option;
static const jrx_option JRX_OPTION_NONE = 0;
static const jrx_option JRX_OPTION_CASE_INSENSITIVE = 1 << 0; // Match case-insentive.
static const jrx_option JRX_OPTION_LAZY = 1 << 1;             // Compute DFA lazily.
static const jrx_option JRX_OPTION_DEBUG = 1 << 2;            // Print debug information.
static const jrx_option JRX_OPTION_NO_CAPTURE = 1 << 3;       // Do not capture subgroups.
static const jrx_option JRX_OPTION_STD_MATCHER = 1 << 4;      // Use the standard matcher.
static const jrx_option JRX_OPTION_DONT_ANCHOR = 1 << 5;      // Don't anchor RE at the beginning.
static const jrx_option JRX_OPTION_FIRST_MATCH = 1 << 6; // Take first match, rather than longest.
// static const jrx_option OPTIONS_INCREMENTAL_DFA = 1 << 4;  // Build DFA incrementally.

// Predefined standard character classes.
typedef enum {
    JRX_STD_CCL_NONE,
    JRX_STD_CCL_EPSILON,
    JRX_STD_CCL_ANY,
    JRX_STD_CCL_LOWER,
    JRX_STD_CCL_UPPER,
    JRX_STD_CCL_WORD,
    JRX_STD_CCL_DIGIT,
    JRX_STD_CCL_BLANK,

    JRX_STD_CCL_NUM, // Count number of std CCLs.
} jrx_std_ccl;

#endif
