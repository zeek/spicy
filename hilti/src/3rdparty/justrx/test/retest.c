// $Id$

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <regex.h>

static void print_error(int rc, regex_t* re, const char* prefix)
{
    char buffer[128];
    regerror(rc, re, buffer, sizeof(buffer));
    printf("%s, %s\n", prefix, buffer);
}

static void do_match(char** argv, int argc, int opt, int options, char* data)
{
    const int max_captures = 20;

    int i;
    int rc;
    regex_t re;
    regmatch_t pmatch[max_captures];

    if ( (argc - opt) == 1 )
        rc = regcomp(&re, argv[opt], REG_EXTENDED | options);
    else {
        jrx_regset_init(&re, -1, REG_EXTENDED | options);
        for ( i = opt; i < argc; i++ ) {
            rc = jrx_regset_add(&re, argv[i], strlen(argv[i]));
            if ( rc != 0 )
                break;
        }

        rc = jrx_regset_finalize(&re);
    }

    if ( rc != 0 ) {
        print_error(rc, &re, "compile error");
        return;
    }

    rc = regexec(&re, data, max_captures, pmatch, 0);

    if ( rc != 0 ) {
        print_error(rc, &re, "pattern not found");
        return;
    }

    printf("match found!\n");

    for ( i = 0; i < max_captures; i++ ) {
        if ( pmatch[i].rm_so != -1 )
            printf("  capture group #%d: (%d,%d)\n", i, pmatch[i].rm_so, pmatch[i].rm_eo);
    }

    regfree(&re);
}

char* readInput()
{
    const int chunk = 5;
    char* buffer = 0;
    int i = 0;

    while ( 1 ) {
        buffer = realloc(buffer, (chunk * ++i) + 1);
        if ( ! buffer ) {
            fprintf(stderr, "cannot alloc\n");
            exit(1);
        }

        char* p = buffer + (chunk * (i - 1));
        size_t n = fread(p, 1, chunk, stdin);
        *(p + chunk) = '\0';

        if ( feof(stdin) )
            break;

        if ( ferror(stdin) ) {
            fprintf(stderr, "error while reading from stdin\n");
            exit(1);
        }
    }

    return buffer;
}


int main(int argc, char** argv)
{
    int opt = 1;
    int debug = 0;
    int lazy = 0;

    int i;
    char* d;

    while ( argc > opt ) {
        if ( strcmp(argv[opt], "-d") == 0 )
            debug = REG_DEBUG;

        else if ( strcmp(argv[opt], "-l") == 0 )
            lazy = REG_LAZY;

        else
            break;

        ++opt;
    }

    if ( (argc - opt) < 1 ) {
        fprintf(stderr, "usage: echo 'data' | retest [-d] [-l] <patterns>\n");
        return 1;
    }

    char* data = readInput();

    fprintf(stderr, "=== Pattern: %s\n", argv[opt]);

    for ( i = opt + 1; i < argc; i++ )
        fprintf(stderr, "             %s\n", argv[i]);

    fputs("=== Data   : ", stderr);
    for ( d = data; *d; d++ ) {
        if ( isprint(*d) )
            fputc(*d, stderr);
        else
            fprintf(stderr, "\\x%02x", (int)*d);
    }
    fputs("\n", stderr);

    fprintf(stderr, "\n=== Standard matcher with subgroups\n");
    do_match(argv, argc, opt, debug | lazy, data);

    fprintf(stderr, "\n=== Standard matcher without subgroups\n");
    do_match(argv, argc, opt, debug | lazy | REG_NOSUB | REG_STD_MATCHER, data);

    fprintf(stderr, "\n=== Minimal matcher\n");
    do_match(argv, argc, opt, debug | lazy | REG_NOSUB, data);

    exit(0);
}
