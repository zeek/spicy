/* Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details. */

%{
#include <string>

#include <spicy/compiler/detail/parser/driver.h>
#include <spicy/compiler/detail/parser/scanner.h>

using token = spicy::detail::parser::Parser::token;
using token_type = spicy::detail::parser::Parser::token_type;

using namespace spicy;
using namespace spicy::detail::parser;

#define yyterminate() return token::EOD

%}

%option c++
%option prefix="Spicy"
%option noyywrap nounput batch debug yylineno

%s EXPRESSION
%s IGNORE_NL

%x DOTTED_ID
%x HOOK_ID
%x RE
%x IGNORE
%x PP_EXPRESSION

%{
#define YY_USER_ACTION yylloc->columns(yyleng);

static hilti::Meta toMeta(spicy::detail::parser::location l) {
    return hilti::Meta(hilti::Location(*l.begin.filename, l.begin.line, l.end.line, l.begin.column, l.end.column));
}

static std::string expandEscapes(Driver* driver, std::string s, spicy::detail::parser::location l) {
    try {
        return hilti::util::expandEscapes(s);
    } catch ( const hilti::rt::Exception& ) {
        driver->error("invalid escape sequence", toMeta(l));
        return "<error>";
    }
}

static std::string preprocessor_directive;

%}

address4  ({digits}"."){3}{digits}
address6  ("["({hexs}:){7}{hexs}"]")|("["0x{hexs}({hexs}|:)*"::"({hexs}|:)*"]")|("["({hexs}|:)*"::"({hexs}|:)*"]")|("["({hexs}|:)*"::"({hexs}|:)*({digits}"."){3}{digits}"]")

attribute \&(bit-order|byte-order|chunked|convert|count|cxxname|default|eod|internal|ipv4|ipv6|hilti_type|length|max-size|no-emit|nosub|on-heap|optional|originator|parse-at|parse-from|priority|requires|responder|size|static|synchronized|transient|try|type|until|until-including|while|have_prototype)
blank     [ \t]
comment   [ \t]*#[^\n]*\n?
digit     [0-9]
digits    {digit}+
hexit     [0-9a-fA-F]
hexs      {hexit}+
E         ([Ee][+-]?{digits})
P         ([Pp][+-]?{digits})
decfloat  {digits}{E}|{digit}*\.{digits}{E}?|{digits}\.{digit}+{E}?
hexfloat  0[xX]({hexit}+{P}|{hexit}*\.{hexit}+{P}?|{hexit}+\.{hexit}+{P}?)
id        [a-zA-Z_]|[a-zA-Z_][a-zA-Z_0-9]*[a-zA-Z_0-9]|[$][$]
property  %[a-zA-Z_][a-zA-Z_0-9-]*
string    \"(\\.|[^\\"])*\"
preprocessor @[a-zA-Z_][a-zA-Z_0-9-]*

%%

%{
    auto range_error_int = [d=driver,l=yylloc]{d->error("integer literal range error", toMeta(*l));};
    auto range_error_real = [d=driver,l=yylloc]{d->error("real literal range error", toMeta(*l));};

    yylloc->step ();
%}

%{
    int next = driver->nextToken();

    if ( next )
        return (token_type)next;
%}

{blank}+              yylloc->step();
[\n]+                 yylloc->lines(yyleng); yylloc->step();
{comment}             yylloc->lines(1); yylloc->step();

__library_type        return token::LIBRARY_TYPE;
addr                  return token::ADDRESS;
add                   return token::ADD;
any                   return token::ANY;
assert                return token::ASSERT;
assert-exception      return token::ASSERT_EXCEPTION;
attribute             return token::ATTRIBUTE;
begin                 return token::BEGIN_;
bitfield              return token::BITFIELD;
bool                  return token::BOOL;
break                 return token::BREAK;
bytes                 return token::BYTES;
case                  return token::CASE;
cast                  return token::CAST;
catch                 return token::CATCH;
const                 return token::CONST;
const_iterator        return token::CONST_ITERATOR;
constant              return token::CONSTANT;
continue              return token::CONTINUE;
cregexp               return token::CREGEXP;
cstring               return token::CSTRING;
default               return token::DEFAULT;
delete                return token::DELETE;
else                  return token::ELSE;
end                   return token::END_;
enum                  return token::ENUM;
exception             return token::EXCEPTION;
export                return token::EXPORT;
file                  return token::FILE;
for                   return token::FOR;
foreach               return token::FOREACH;
from                  return token::FROM;
function              return token::FUNCTION;
global                return token::GLOBAL;
ident                 return token::IDENT;
if                    return token::IF;
import                return token::IMPORT;
in                    return token::IN;
!in                   return token::NOT_IN;
inout                 return token::INOUT;
int16                 return token::INT16;
int32                 return token::INT32;
int64                 return token::INT64;
int8                  return token::INT8;
interval              return token::INTERVAL;
interval_ns           return token::INTERVAL_NS;
iterator              return token::ITERATOR;
list                  return token::LIST;
local                 return token::LOCAL;
map                   return token::MAP;
mark                  return token::MARK;
mod                   return token::MOD;
module                return token::MODULE;
net                   return token::NET;
new                   return token::NEW;
object                return token::OBJECT;
on                    return token::ON;
optional              return token::OPTIONAL;
port                  return token::PORT;
print                 return token::PRINT;
priority              return token::PRIORITY;
private               return token::PRIVATE;
property              return token::PROPERTY;
public                return token::PUBLIC;
real                  return token::REAL;
regexp                return token::REGEXP;
return                return token::RETURN;
set                   return token::SET;
sink                  return token::SINK;
stop                  return token::STOP;
stream                return token::STREAM;
string                return token::STRING;
struct                return token::STRUCT;
switch                return token::SWITCH;
throw                 return token::THROW;
time                  return token::TIME;
time_ns               return token::TIME_NS;
timer                 return token::TIMER;
try                   return token::TRY;
tuple                 return token::TUPLE;
type                  return token::TYPE;
uint16                return token::UINT16;
uint32                return token::UINT32;
uint64                return token::UINT64;
uint8                 return token::UINT8;
unit                  return token::UNIT;
unset                 return token::UNSET;
var                   return token::VAR;
vector                return token::VECTOR;
view                  return token::VIEW;
void                  return token::VOID;
while                 return token::WHILE;

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
!<                    return token::HOOK_PARSE;
!>                    return token::HOOK_COMPOSE;
\$\$                  return token::DOLLARDOLLAR;
<EXPRESSION>\>\>      return token::SHIFTRIGHT;


False                 yylval->build(false); return token::CBOOL;
True                  yylval->build(true); return token::CBOOL;
None                  return token::NONE;
Null                  return token::CNULL;

{attribute}           yylval->build(std::string(yytext)); return token::ATTRIBUTE;
<INITIAL>{property}   yylval->build(std::string(yytext)); return token::PROPERTY;
{digits}\/(tcp|udp)   yylval->build(std::string(yytext)); return token::CPORT;
{address4}            yylval->build(std::string(yytext)); return token::CADDRESS;
{address6}            yylval->build(std::string(yytext, 1, strlen(yytext) - 2)); return token::CADDRESS;

{digits}|0x{hexs}     yylval->build(hilti::util::chars_to_uint64(yytext, 0, range_error_int)); return token::CUINTEGER;
{string}              yylval->build(expandEscapes(driver, std::string(yytext, 1, strlen(yytext) - 2), *yylloc)); return token::CSTRING;
b{string}             yylval->build(expandEscapes(driver, std::string(yytext, 2, strlen(yytext) - 3), *yylloc)); return token::CBYTES;
'.'                   yylval->build(static_cast<uint64_t>(*(yytext +1))); return token::CUINTEGER;

{decfloat}|{hexfloat} yylval->build(hilti::util::chars_to_double(yytext, range_error_real)); return token::CUREAL;

{id}                   yylval->build(std::string(yytext)); return token::IDENT;
{id}(::{id}){1,}(::{property})?       yylval->build(std::string(yytext)); return token::SCOPED_IDENT;
{id}(::{property})?    yylval->build(std::string(yytext)); return token::SCOPED_IDENT;
\$[1-9][0-9]*          yylval->build(hilti::util::chars_to_uint64(yytext + 1, 10, range_error_int)); return token::DOLLAR_NUMBER;
\${id}                 yylval->build(std::string(yytext + 1)); return token::DOLLAR_IDENT;

[][!$?.,=:;<>(){}/|*/&^%!+~-] return (token_type) yytext[0];

.                     driver->error("invalid character", toMeta(*yylloc));

<RE>(\\.|[^\\\/])*    yylval->build(hilti::util::replace(yytext, "\\/", "/")); return token::CREGEXP;
<RE>[/\\\n]           return (token_type) yytext[0];

<DOTTED_ID>%?{id}(\.{id})*  yylval->build(std::string(yytext)); return token::DOTTED_IDENT;
<DOTTED_ID>{blank}+       yylloc->step();
<DOTTED_ID>[\n]+          yylloc->lines(yyleng); yylloc->step();

<HOOK_ID>%?{id}(\.{id})*  yylval->build(std::string(yytext)); return token::HOOK_IDENT;
<HOOK_ID>({id}::){1,}%?{id}(\.{id})*  yylval->build(std::string(yytext)); return token::HOOK_IDENT;
<HOOK_ID>{blank}+       yylloc->step();
<HOOK_ID>[\n]+          yylloc->lines(yyleng); yylloc->step();

{preprocessor}          preprocessor_directive = yytext; yy_push_state(PP_EXPRESSION);
<PP_EXPRESSION>[^\n]*(\n|$) yy_pop_state(); yylloc->lines(1); driver->processPreprocessorLine(preprocessor_directive, hilti::rt::trim(yytext), toMeta(*yylloc));

<IGNORE>{preprocessor}  preprocessor_directive = yytext; yy_push_state(PP_EXPRESSION);
<IGNORE>[\n]+           yylloc->lines(yyleng); yylloc->step(); /* eat */
<IGNORE>.               /* eat */

%%

int SpicyFlexLexer::yylex()
{
    assert(false); // Shouldn't be called.
    return 0;
}

void spicy::detail::parser::Scanner::enablePatternMode()
{
    yy_push_state(RE);
}

void spicy::detail::parser::Scanner::disablePatternMode()
{
    yy_pop_state();
}

static int expression_mode = 0;

void spicy::detail::parser::Scanner::enableExpressionMode()
{
    if ( expression_mode++ >= 0 )
        yy_push_state(EXPRESSION);
}

void spicy::detail::parser::Scanner::disableExpressionMode()
{
    if ( --expression_mode >= 0 )
        yy_pop_state();
}

void spicy::detail::parser::Scanner::enableDottedIDMode()
{
    yy_push_state(DOTTED_ID);
}

void spicy::detail::parser::Scanner::disableDottedIDMode()
{
    yy_pop_state();
}

void spicy::detail::parser::Scanner::enableHookIDMode()
{
    yy_push_state(HOOK_ID);
}

void spicy::detail::parser::Scanner::disableHookIDMode()
{
    yy_pop_state();
}

void spicy::detail::parser::Scanner::setIgnoreMode(bool enable)
{
    // Note to self: use YY_START, not yy_top_state(), that's the *previous* state.

    if ( enable && YY_START != IGNORE )
            yy_push_state(IGNORE);

    if ( ! enable && YY_START == IGNORE )
        yy_pop_state();
}
