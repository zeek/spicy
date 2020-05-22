
/* Loosely based on Bro's re-scan.l */

%{

#ifndef __clang_analyzer__

#undef yyerror
#define yyerror RE_Error

#include <justrx/jrx-intern.h>
#include <justrx/nfa.h>
#include <justrx/util.h>
#include <justrx/autogen/re-parse.h>

void RE_Error(yyscan_t scanner, const char* msg);

%}

%x COUNT CCL_FIRST CCL ACCEPT_ID
%option nounput noyywrap reentrant bison-bridge prefix="RE_"

ESCSEQ          (\\([^\n]|[0-7]+|x[[:xdigit:]]{2}))

CCL_EXPR        ("[:"[[:alpha:]]+":]")
CCL_CHAR_FIRST  ([^\\]|{CCL_EXPR}|{ESCSEQ})
CCL_CHAR        ([^\\\]]|{CCL_EXPR}|{ESCSEQ})

ACCEPT_ID       \{#[[:digit:]]+\}

%%

<INITIAL>{
    {ACCEPT_ID}     yylval->count = atoi(yytext+2); return TOK_ACCEPT_ID;

	"{"/[[:digit:]] BEGIN(COUNT); return '{';
	"["             BEGIN(CCL_FIRST); return '[';

	[|*+?.(){}]	    return yytext[0];

	"^"		yylval->assertion = JRX_ASSERTION_BOL; return TOK_ASSERTION;
	"$"		yylval->assertion = JRX_ASSERTION_EOL; return TOK_ASSERTION;
	"\\b"	yylval->assertion = JRX_ASSERTION_WORD_BOUNDARY; return TOK_ASSERTION;
	"\\B"	yylval->assertion = JRX_ASSERTION_NOT_WORD_BOUNDARY; return TOK_ASSERTION;

	.       yylval->cp = yytext[0]; return TOK_CODEPOINT;
}

<CCL_FIRST>{
	"^"            return TOK_NEGATE_CCL;
	.              BEGIN(CCL); yylval->cp = yytext[0]; return TOK_CODEPOINT;
}

<CCL>{
	-/[^\]]         return '-';
	[^\]]           yylval->cp = yytext[0]; return TOK_CODEPOINT;
	"]"             BEGIN(INITIAL); return ']';
}

<CCL_FIRST,CCL>{
	"[:lower:]"     BEGIN(CCL); yylval->dynccl = JRX_STD_CCL_LOWER; return TOK_DYNCCL;
	"[:upper:]"     BEGIN(CCL); yylval->dynccl = JRX_STD_CCL_UPPER; return TOK_DYNCCL;
	"[:digit:]"     BEGIN(CCL); yylval->dynccl = JRX_STD_CCL_DIGIT; return TOK_DYNCCL;
	"[:blank:]"     BEGIN(CCL); yylval->dynccl = JRX_STD_CCL_BLANK; return TOK_DYNCCL;
	{CCL_EXPR}      RE_Error(yyscanner, "bad character class"); BEGIN(CCL); return TOK_DYNCCL;
}

<COUNT>{
	[[:digit:]]+    yylval->count = atoi(yytext); return TOK_COUNT;
	","             return ',';
	"}"             BEGIN(INITIAL); return '}';
	.	            RE_Error(yyscanner, "bad character inside {}'s"); BEGIN(INITIAL); return '}';
}

<INITIAL,CCL_FIRST,CCL>{ESCSEQ}	{
			const char* esc_text = yytext + 1;
			yylval->cp = jrx_expand_escape(esc_text);

			if ( YY_START == CCL_FIRST )
				BEGIN(CCL);

			return TOK_CODEPOINT;
			}

%%

void RE_Error(yyscan_t scanner, const char* msg)
{
    const char** errmsg = RE_get_extra(scanner);
    if ( errmsg && ! *errmsg )
        *errmsg = msg;
}

#endif
