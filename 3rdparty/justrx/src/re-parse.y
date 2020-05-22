%{

#ifndef __clang_analyzer__

#undef yyerror
#define yyerror RE_Error

#include <justrx/jrx-intern.h>
#include <justrx/nfa.h>

#include <stdio.h>

// NOTE: This function is not called `RE_error` to avoid a name collision with a Bison-internal name.
extern void RE_Error(void* scanner, jrx_nfa_context* nfactx, jrx_nfa** nfa, const char* msg);
extern int RE_lex(void* yylval_param, void* yyscanner);

#define parse_error(msg) RE_Error(scanner, 0, 0, msg)

%}

%define api.prefix {RE_}
%code provides { #define YYSTYPE RE_STYPE }

%define api.pure
%file-prefix "re-parse"
%defines

%lex-param{void* scanner}
%parse-param{void* scanner}
%parse-param{jrx_nfa_context* nfactx}
%parse-param{jrx_nfa** nfa}

%token TOK_ASSERTION TOK_CODEPOINT TOK_NEGATE_CCL TOK_COUNT TOK_DYNCCL TOK_ACCEPT_ID

%union {
    jrx_char cp;
    jrx_assertion assertion;
    jrx_std_ccl dynccl;
    int count;

    jrx_nfa* nfa;
    jrx_ccl* ccl;
}

%type <cp> TOK_CODEPOINT
%type <assertion> TOK_ASSERTION assertions
%type <dynccl> TOK_DYNCCL
%type <count> TOK_COUNT TOK_ACCEPT_ID opt_count opt_accept_id

%type <ccl> ccl ccl_elem
%type <nfa> complete_regexp regexp alternatives singletons singleton

%%

complete_regexp : regexp opt_accept_id
                  {
                  *nfa = $1;
                  *nfa = nfa_set_capture(*nfa, 0);

                  /* Add a .* if requested. */
                  if ( nfactx->options & JRX_OPTION_DONT_ANCHOR ) {
                      jrx_nfa* any = nfa_from_ccl(nfactx, ccl_any(nfactx->ccls));
                      *nfa = nfa_concat(nfa_iterate(any, 0, -1), *nfa, 0);
                      }

                  if ( $2 > 0 )
                      *nfa = nfa_set_accept(*nfa, $2);
                   }
                ;

regexp : alternatives
         { $$ = $1; }
       ;

opt_accept_id : TOK_ACCEPT_ID
                { $$ = $1; }
              |
                { $$ = -1; }
              ;

alternatives : singletons '|' alternatives
               { $$ = nfa_alternative($1, $3); }
             | singletons
               { $$ = $1; }
             ;

singletons : singleton singletons
             { $$ = nfa_concat($1, $2, 0); }
           | singleton assertions singletons
             {
                 jrx_ccl* ccl = ccl_epsilon(nfactx->ccls);
                 ccl = ccl_add_assertions(ccl, $2);
                 $$ = nfa_concat($1, $3, ccl);
             }

           | singleton
             { $$ = $1; }
           ;

assertions : TOK_ASSERTION
             { $$ = $1; }

           |  TOK_ASSERTION assertions
             { $$ = ($1 | $2); }

singleton : singleton '*'
            { $$ = nfa_iterate($1, 0, -1); }

          | singleton '+'
            { $$ = nfa_iterate($1, 1, -1); }

          | singleton '?'
            { $$ = nfa_iterate($1, 0, 1); }

          | singleton '{' opt_count ',' opt_count '}'
            {
                if ( $3 > $5 && $5 >= 0 )
                    parse_error("bad interation value");
                else
                    $$ = nfa_iterate($1, $3, $5);
            }

          | singleton '{' TOK_COUNT '}'
            {
                if ( $3 < 0 )
                    parse_error("bad interation value");
                else
                    $$ = nfa_iterate($1, $3, $3);
            }

          | '.'
            { $$ = nfa_from_ccl(nfactx, ccl_any(nfactx->ccls)); }

          | '[' ccl ']'
            { $$ = nfa_from_ccl(nfactx, $2); }

          | '[' TOK_NEGATE_CCL ccl ']'
            { $$ = nfa_from_ccl(nfactx, ccl_negate($3)); }

          | '('
            { $<count>$ = ++nfactx->max_capture; }

            regexp ')'
            { $$ = nfa_set_capture($3, $<count>2); }

          | TOK_CODEPOINT
            { $$ = nfa_from_ccl(nfactx, ccl_from_range(nfactx->ccls, $1, $1 + 1)); }

          |
            { $$ = nfa_empty(nfactx); }
          ;

opt_count : TOK_COUNT
            { $$ = $1; }
          |
            { $$ = -1; }

ccl : ccl_elem ccl
      { $$ = ccl_join($1, $2); }
    | ccl_elem
      { $$ = $1; }


ccl_elem : TOK_CODEPOINT '-' TOK_CODEPOINT
           { $$ = ccl_from_range(nfactx->ccls, $1, $3 + 1); }

         | TOK_DYNCCL
           { $$ = ccl_from_std_ccl(nfactx->ccls, $1); }

         | TOK_CODEPOINT
           { $$ = ccl_from_range(nfactx->ccls, $1, $1 + 1); }
      ;


%%

#endif
