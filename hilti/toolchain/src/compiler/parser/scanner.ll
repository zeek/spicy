/* Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details. */

%{
#include <string>

#include <hilti/compiler/detail/parser/driver.h>
#include <hilti/compiler/detail/parser/scanner.h>

using token = hilti::detail::parser::Parser::token;
using token_type = hilti::detail::parser::Parser::token_type;

using namespace hilti;
using namespace hilti::detail::parser;

#define yyterminate() return token::EOD;

%}

%option c++
%option prefix="Hilti"
%option noyywrap nounput batch debug yylineno

%s EXPRESSION
%s IGNORE_NL

%x DOTTED_ID
%x RE

%{
#define YY_USER_ACTION yylloc->columns(yyleng);

static hilti::Meta toMeta(hilti::detail::parser::location l) {
    return hilti::Meta(hilti::Location(*l.begin.filename, l.begin.line, l.end.line, l.begin.column, l.end.column));
}

static std::string expandEscapes(Driver* driver, std::string s, hilti::detail::parser::location l) {
    try {
        return hilti::util::expandEscapes(s);
    } catch ( const hilti::rt::Exception& ) {
        driver->error("invalid escape sequence", toMeta(l));
        return "<error>";
    }
}

%}

address4  ({digits}"."){3}{digits}
address6  ("["({hexs}:){7}{hexs}"]")|("["0x{hexs}({hexs}|:)*"::"({hexs}|:)*"]")|("["({hexs}|:)*"::"({hexs}|:)*"]")|("["({hexs}|:)*"::"({hexs}|:)*({digits}"."){3}{digits}"]")

attribute \&[a-zA-Z_][a-zA-Z_0-9-]*
blank     [ \t]
comment   [ \t]*#[^\n]*\n?
digit     [0-9]
digits    {digit}+
hexit     [0-9a-fA-F]
hexs      {hexit}+
E         ([Ee][+-]?{digits})
P         ([Pp][+-]?{digits})
decfloat  {digits}{E}|{digit}*\.{digits}{E}?|{digits}\.{digit}*{E}?
hexfloat  0[xX]({hexit}+{P}|{hexit}*\.{hexit}+{P}?|{hexit}+\.{hexit}*{P}?)
id        [a-zA-Z_]|[a-zA-Z_][a-zA-Z_0-9-]*[a-zA-Z_0-9]|[$][$]
property  %[a-zA-Z_][a-zA-Z_0-9-]*
string    \"(\\.|[^\\"])*\"

%%

%{
    auto range_error_int = [d=driver, l=yylloc] { d->error("integer literal range error", toMeta(*l)); };
    auto range_error_real = [d=driver, l=yylloc] { d->error("real literal range error", toMeta(*l)); };

    yylloc->step ();
%}

{blank}+              yylloc->step();
[\n]+                 yylloc->lines(yyleng); yylloc->step();
{comment}             yylloc->lines(1); yylloc->step();

~finally              return token::FINALIZE;
__library_type        return token::LIBRARY_TYPE;
addr                  return token::ADDRESS;
add                   return token::ADD;
any                   return token::ANY;
assert                return token::ASSERT;
assert-exception      return token::ASSERT_EXCEPTION;
auto                  return token::AUTO;
begin                 return token::BEGIN_;
bool                  return token::BOOL;
break                 return token::BREAK;
bytes                 return token::BYTES;
case                  return token::CASE;
cast                  return token::CAST;
catch                 return token::CATCH;
const                 return token::CONST;
const_iterator        return token::CONST_ITERATOR;
continue              return token::CONTINUE;
copy                  return token::COPY;
declare               return token::DECLARE;
default               return token::DEFAULT;
delete                return token::DELETE;
else                  return token::ELSE;
end                   return token::END_;
enum                  return token::ENUM;
error                 return token::ERROR;
exception             return token::EXCEPTION;
extern                return token::EXTERN;
extern-no-suspend     return token::EXTERN_NO_SUSPEND;
for                   return token::FOR;
from                  return token::FROM;
function              return token::FUNCTION;
global                return token::GLOBAL;
hook                  return token::HOOK;
if                    return token::IF;
import                return token::IMPORT;
in                    return token::IN;
!in                   return token::NOT_IN;
init                  return token::INIT;
inout                 return token::INOUT;
int                   return token::INT;
interval              return token::INTERVAL;
iterator              return token::ITERATOR;
list                  return token::LIST;
local                 return token::LOCAL;
map                   return token::MAP;
method                return token::METHOD;
module                return token::MODULE;
move                  return token::MOVE;
net                   return token::NETWORK;
new                   return token::NEW;
optional              return token::OPTIONAL;
port                  return token::PORT;
preinit               return token::PREINIT;
private               return token::PRIVATE;
public                return token::PUBLIC;
real                  return token::REAL;
regexp                return token::REGEXP;
result                return token::RESULT;
return                return token::RETURN;
set                   return token::SET;
stream                return token::STREAM;
string                return token::STRING;
strong_ref            return token::STRONG_REF;
struct                return token::STRUCT;
switch                return token::SWITCH;
throw                 return token::THROW;
time                  return token::TIME;
try                   return token::TRY;
tuple                 return token::TUPLE;
type                  return token::TYPE;
typeinfo              return token::TYPEINFO;
uint                  return token::UINT;
union                 return token::UNION;
unpack                return token::UNPACK;
unset                 return token::UNSET;
value_ref             return token::VALUE_REF;
vector                return token::VECTOR;
view                  return token::VIEW;
void                  return token::VOID;
weak_ref              return token::WEAK_REF;
while                 return token::WHILE;
yield                 return token::YIELD;

!=                    return token::NEQ;
\&\&                  return token::AND;
\+=                   return token::PLUSASSIGN;
--                    return token::MINUSMINUS;
-=                    return token::MINUSASSIGN;
\/=                   return token::DIVIDEASSIGN;
\*=                   return token::TIMESASSIGN;
\<\<                  return token::SHIFTLEFT;
\<=                   return token::LEQ;
==                    return token::EQ;
\>=                   return token::GEQ;
\?\.                  return token::HASATTR;
\.\?                  return token::TRYATTR;
\*\*                  return token::POW;
\+\+                  return token::PLUSPLUS;
\|\|                  return token::OR;
\.\.                  return token::DOTDOT;
->                    return token::ARROW;
\$\$                  return token::DOLLARDOLLAR;
<EXPRESSION>\>\>      return token::SHIFTRIGHT;


\"C-HILTI\"           yylval->emplace<std::string>(yytext, 1, strlen(yytext) - 2); return token::CSTRING;
\"C\"                 yylval->emplace<std::string>(yytext, 1, strlen(yytext) - 2); return token::CSTRING;

Null                  return token::CNULL;

False                 yylval->emplace<bool>(false); return token::CBOOL;
True                  yylval->emplace<bool>(true); return token::CBOOL;

{digits}|0x{hexs}     yylval->emplace<uint64_t>(hilti::util::chars_to_uint64(yytext, 0, range_error_int)); return token::CUINTEGER;
'.'                   yylval->emplace<uint64_t>(*(yytext +1)); return token::CUINTEGER;

{decfloat}|{hexfloat} yylval->emplace<double>(hilti::util::chars_to_double(yytext, range_error_real)); return token::CUREAL;
{string}              yylval->emplace<str>(expandEscapes(driver, std::string(yytext, 1, strlen(yytext) - 2), *yylloc)); return token::CSTRING;
b{string}             yylval->emplace<str>(expandEscapes(driver, std::string(yytext, 2, strlen(yytext) - 3), *yylloc)); return token::CBYTES;
{digits}\/(tcp|udp)   yylval->emplace<str>(yytext); return token::CPORT;
{address4}            yylval->emplace<str>(yytext); return token::CADDRESS;
{address6}            yylval->emplace<str>(yytext, 1, strlen(yytext) - 2); return token::CADDRESS;

{id}                  yylval->emplace<str>(yytext); return token::IDENT;
{attribute}           yylval->emplace<str>(yytext); return token::ATTRIBUTE;
{property}            yylval->emplace<str>(yytext); return token::PROPERTY;
{id}(::{id}){1,}      yylval->emplace<str>(yytext); return token::SCOPED_IDENT;
{id}(::~finally)      yylval->emplace<str>(yytext); return token::SCOPED_FINALIZE;

[][!$?.,=:;<>(){}/|*/&^%!+~-] return (token_type) yytext[0];

.                     driver->error("invalid character", toMeta(*yylloc));

<RE>(\\.|[^\\\/])*    yylval->emplace<str>(hilti::util::replace(yytext, "\\/", "/")); return token::CREGEXP;
<RE>[/\\\n]           return (token_type) yytext[0];

<DOTTED_ID>{id}(\.{id})*  yylval->emplace<str>(yytext); return token::DOTTED_IDENT;
<DOTTED_ID>{blank}+       yylloc->step();
<DOTTED_ID>[\n]+          yylloc->lines(yyleng); yylloc->step();

%%

int HiltiFlexLexer::yylex()
{
    assert(false); // Shouldn't be called.
    return 0;
}

void hilti::detail::parser::Scanner::enablePatternMode()
{
    yy_push_state(RE);
}

void hilti::detail::parser::Scanner::disablePatternMode()
{
    yy_pop_state();
}

void hilti::detail::parser::Scanner::enableExpressionMode()
{
    yy_push_state(EXPRESSION);
}

void hilti::detail::parser::Scanner::disableExpressionMode()
{
    yy_pop_state();
}

void hilti::detail::parser::Scanner::enableDottedIDMode()
{
    yy_push_state(DOTTED_ID);
}

void hilti::detail::parser::Scanner::disableDottedIDMode()
{
    yy_pop_state();
}
