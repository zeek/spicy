// $Id$

#include "jrx-intern.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>

// Copied and adapted from Bro.
jrx_char jrx_expand_escape(const char* s)
{
    switch ( *(s++) ) {
    case 'b':
        return '\b';
    case 'f':
        return '\f';
    case 'n':
        return '\n';
    case 'r':
        return '\r';
    case 't':
        return '\t';
    case 'a':
        return '\a';
    case 'v':
        return '\v';

    case '0':
    case '1':
    case '2':
    case '3':
    case '4':
    case '5':
    case '6':
    case '7': {
        // \<octal>{1,3}
        --s; // put back the first octal digit
        const char* start = s;

        // Don't increment inside loop control
        // because if isdigit() is a macro it might
        // expand into multiple increments ...
        //
        // Here we define a maximum length for escape sequence
        // to allow easy handling of string like: "^H0" as
        // "\0100".
        //
        int len;
        for ( len = 0; len < 3 && isascii(*s) && isdigit(*s); ++s, ++len )
            ;

        int result;
        if ( sscanf(start, "%3o", &result) != 1 ) {
            // warn("bad octal escape: ", start);
            result = 0;
        }

        return result;
    }

    case 'x': {
        /* \x<hex> */
        const char* start = s;

        // Look at most 2 characters, so that "\x0ddir" -> "^Mdir".
        int len;
        for ( len = 0; len < 2 && isascii(*s) && isxdigit(*s); ++s, ++len )
            ;

        int result;
        if ( sscanf(start, "%2x", &result) != 1 ) {
            // warn("bad hexadecimal escape: ", start);
            result = 0;
        }

        return result;
    }

    default:
        return s[-1];
    }
}

void jrx_internal_error(const char* msg)
{
    fprintf(stderr, "jitre internal error: %s", msg);
    abort();
}
