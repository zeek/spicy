// $Id$
//
/// High-level regexp interface, partially matching POSIX functions.

#ifndef JRX_H
#define JRX_H

#include <stdint.h>
#include <stdlib.h>

// Predefined types.
typedef uint32_t jrx_char;         ///< A single codepoint.
typedef int32_t jrx_offset;        ///< Offset in input stream.
typedef int16_t jrx_accept_id;     ///< ID for an accepting state.
typedef uint32_t jrx_nfa_state_id; // ID for an NFA state.
typedef uint32_t jrx_dfa_state_id; // ID for a DFA state.
typedef uint16_t jrx_ccl_id;       // ID for a CCL.

typedef uint16_t jrx_assertion; ///< Type for zero-width assertions.
static const jrx_assertion JRX_ASSERTION_NONE = 0;
static const jrx_assertion JRX_ASSERTION_BOL = 1 << 1;               ///< Beginning of line.
static const jrx_assertion JRX_ASSERTION_EOL = 1 << 2;               ///< End of line.
static const jrx_assertion JRX_ASSERTION_BOD = 1 << 3;               ///< Beginning of data.
static const jrx_assertion JRX_ASSERTION_EOD = 1 << 4;               ///< End of data.
static const jrx_assertion JRX_ASSERTION_WORD_BOUNDARY = 1 << 5;     ///< A word boundary.
static const jrx_assertion JRX_ASSERTION_NOT_WORD_BOUNDARY = 1 << 6; ///< Not a word boundary.
static const jrx_assertion JRX_ASSERTION_CUSTOM1 = 1 << 12;          ///< Assertion for custom usage.
static const jrx_assertion JRX_ASSERTION_CUSTOM2 = 1 << 13;          ///< Assertion for custom usage.
static const jrx_assertion JRX_ASSERTION_CUSTOM3 = 1 << 14;          ///< Assertion for custom usage.
static const jrx_assertion JRX_ASSERTION_CUSTOM4 = 1 << 15;          ///< Assertion for custom usage.

struct jrx_nfa;
struct jrx_dfa;
struct set_match_accept;
struct jrx_match_state;
typedef struct jrx_match_state jrx_match_state;
typedef struct jrx_regex_t jrx_regex_t;

struct jrx_match_state {
    jrx_offset offset;      ///< Offset of next input byte.
    jrx_offset begin;       // Offset of first cp; will be added to pmatch.
    struct jrx_dfa* dfa;    // The DFA we're matching with.
    jrx_dfa_state_id state; // Current state.
    jrx_char previous;      // Previous code point seen (valid iff offset > 0)
    int cflags;             // RE_* flags that were used for compilation.

    // The following are only used with the full matcher.
    struct set_match_accept* accepts; // Accepts we have encountered so far.
    int current_tags;                 // Current set of position of tags (0 or 1).
    jrx_offset* tags1;                // 1st & 2nd set of position of tags; (we use
    jrx_offset* tags2;                // a double-buffering scheme here).
    int tags1_size;                   // Current sizes of 1st and 2nd tags sets.
    int tags2_size;

    // The following are only used with the minimal matcher.
    jrx_accept_id acc;
};

struct jrx_regex_t {
    size_t re_nsub;      ///< Number of capture expressions in regular expression (POSIX).
    int cflags;          // RE_* flags for compilation.
    int nmatch;          // Max. number of subexpression caller is interested in; -1 for all.
    struct jrx_nfa* nfa; // Compiled NFA, or NULL.
    struct jrx_dfa* dfa; // Compiled DFA, or NULL.
    const char* errmsg;  // Most recent error message, or NULL if none.
};

typedef jrx_offset regoff_t;

typedef struct jrx_regmatch_t {
    regoff_t rm_so; //< Zero-based start offset of match (POSIX).
    regoff_t rm_eo; //< End offset of match (POSIX). It locates the first byte after the match. (POSIX).
} jrx_regmatch_t;

// POSIX options. We use macros here for compatibility with code using
// ifdef's on them and/or expecting integers.
#define REG_BASIC 0 // sic! (but not supported anyway)
#define REG_EXTENDED (1 << 0) ///< "Extended" regular expression syntax (we only one we support).
#define REG_NOSUB (1 << 1)

// FIXME: The following are not implemented currently.
#define REG_ICASE (1 << 2)
#define REG_NEWLINE (1 << 3)
#define REG_NOTBOL (1 << 4)
#define REG_NOTEOL (1 << 5)

// Non-standard options.
#define REG_DEBUG (1 << 6) //< Enable debugging output to stderr.
#define REG_STD_MATCHER (1 << 7) //< Force usage of the (slower) standard matcher even with REG_NOSUB.
#define REG_ANCHOR                                                                                                     \
    (1 << 8) //< Anchor matching at beginning. The effect is that of an implicit '^' at the
             // beginning.
#define REG_LAZY (1 << 9) //< Build DFA incrementally.
#define REG_FIRST_MATCH (1 << 10) //< Take first match, rather than longest.

// Non-standard error codes..
#define REG_OK 0 //< Everything is fine.
#define REG_NOTSUPPORTED 1 //< A non-supported feature has been used.

// POSIX error codes.
#define REG_BADPAT 3 //< A bad pattern was giving for compilation.
#define REG_NOMATCH 4 //< No match has been found.
#define REG_EMEM 5 //< Running out of memory.

// We actually do not raise these POSIX errors but define them for
// completeness.
#define REG_ECOLLATE 10
#define REG_ECTYPE 11
#define REG_EESCAPE 12
#define REG_ESUBREG 13
#define REG_EBRACK 14
#define REG_EPAREN 15
#define REG_EBRACE 16
#define REG_BADBR 17
#define REG_ERANGE 18
#define REG_ESPACE 19
#define REG_BADRPT 20
#define REG_ENEWLINE 21
#define REG_ENULL 22
#define REG_ECOUNT 23
#define REG_BADESC 24
#define REG_EHUNG 25
#define REG_EBUS 26
#define REG_EFAULT 27
#define REG_EFLAGS 28
#define REG_EDELIM 29

// These are POSIX compatible.
extern int jrx_regcomp(jrx_regex_t* preg, const char* pattern, int cflags);
extern size_t jrx_regerror(int errcode, const jrx_regex_t* preg, char* errbuf, size_t errbuf_size);
extern int jrx_regexec(const jrx_regex_t* preg, const char* string, size_t nmatch, jrx_regmatch_t pmatch[], int eflags);
extern void jrx_regfree(jrx_regex_t* preg);

// These are non-POSIX extensions.
extern void jrx_regset_init(jrx_regex_t* preg, int nmatch, int cflags);
extern void jrx_regset_done(jrx_regex_t* preg, int cflags);
extern int jrx_regset_add(jrx_regex_t* preg, const char* pattern, unsigned int len);
extern int jrx_regset_finalize(jrx_regex_t* preg);
extern int jrx_regexec_partial(const jrx_regex_t* preg, const char* buffer, unsigned int len, jrx_assertion first,
                               jrx_assertion last, jrx_match_state* ms, int find_partial_matches);
extern int jrx_reggroups(const jrx_regex_t* preg, jrx_match_state* ms, size_t nmatch, jrx_regmatch_t pmatch[]);
extern int jrx_num_groups(jrx_regex_t* preg);
extern int jrx_is_anchored(jrx_regex_t* preg);
extern int jrx_can_transition(jrx_match_state* ms);
extern int jrx_current_accept(jrx_match_state* ms);

extern jrx_match_state* jrx_match_state_init(const jrx_regex_t* preg, jrx_offset begin, jrx_match_state* ms);
extern void jrx_match_state_copy(const jrx_match_state* from, jrx_match_state* to); // supports only min-matcher state
extern void jrx_match_state_done(jrx_match_state* ms);

#endif
