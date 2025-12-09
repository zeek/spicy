/* Copyright (c) 2020-now by the Zeek Project. See LICENSE for details. */

/* This grammar is written against the bison-3.3 API. If an older Bison version
 * was detected we perform preprocessing to support versions down to at least
 * bison-3.0, see the CMake macro `BISON_TARGET_PP`. */
%require "3.3"

%skeleton "lalr1.cc"                          /*  -*- C++ -*- */
%defines

%{
namespace hilti { namespace detail { class Parser; } }

#include <hilti/compiler/context.h>
#include <hilti/compiler/detail/parser/driver.h>
#include <hilti/ast/builder/all.h>

%}

%locations
%initial-action
{
    @$.begin.filename = @$.end.filename = driver->currentFile();
};

%parse-param {Driver* driver} {Builder* builder}
%lex-param   {Driver* driver}

%define api.namespace {hilti::detail::parser}
%define api.parser.class {Parser}
%define api.value.type variant
%define parse.error verbose

%debug
%verbose

%glr-parser
%expect 93
%expect-rr 167

%{

#include <hilti/compiler/detail/parser/scanner.h>

#undef yylex
#define yylex driver->scanner()->lex

static hilti::Meta toMeta(hilti::detail::parser::location l) {
    return hilti::Meta(hilti::Location(*l.begin.filename, l.begin.line, l.end.line, l.begin.column,
                                       (l.end.column > 0 ? l.end.column - 1 : 0)));
}

static hilti::QualifiedType* iteratorForType(hilti::Builder* builder, hilti::QualifiedType* t, hilti::Meta m) {
    if ( auto iter = t->type()->iteratorType() )
        return iter;
    else {
        hilti::logger().error(hilti::util::fmt("type '%s' is not iterable", *t), m.location());
        return builder->qualifiedType(builder->typeError(), hilti::Constness::Const);
        }
}

static hilti::QualifiedType* viewForType(hilti::Builder* builder, hilti::QualifiedType* t, hilti::Meta m) {
    if ( auto v = t->type()->viewType() )
        return v;
    else {
        hilti::logger().error(hilti::util::fmt("type '%s' is not viewable", *t), m.location());
        return builder->qualifiedType(builder->typeError(), hilti::Constness::Const);
        }
}

#define __loc__ toMeta(yylhs.location)

#define YYLLOC_DEFAULT(Current, Rhs, N)                                                                                \
do {                                                                                                                   \
    bool done = false;                                                                                                 \
    for ( int i = 1; i <= N; i++ ) {                                                                                   \
        if ( YYRHSLOC(Rhs, i).begin.line != YYRHSLOC(Rhs, i).end.line ||                                               \
             YYRHSLOC(Rhs, i).begin.column != YYRHSLOC(Rhs, i).end.column ) {                                          \
            (Current).begin = YYRHSLOC(Rhs, i).begin;                                                                  \
            (Current).end = YYRHSLOC(Rhs, N).end;                                                                      \
            done = true;                                                                                               \
            break;                                                                                                     \
        }                                                                                                              \
    }                                                                                                                  \
    if ( ! done )                                                                                                      \
        (Current).begin = (Current).end = YYRHSLOC(Rhs, 0).end;                                                        \
} while ( false )

static int _field_width = 0;

%}

%token <std::string> IDENT          "identifier"
%token <std::string> SCOPED_IDENT   "scoped identifier"
%token <std::string> SCOPED_FINALIZE "scoped ~finally"
%token <std::string> DOTTED_IDENT   "dotted identifier"
%token <std::string> ATTRIBUTE      "attribute"
%token <std::string> PROPERTY       "property"

%token <std::string> CSTRING        "string value"
%token <std::string> CBYTES         "bytes value"
%token <std::string> CREGEXP        "regular expression value"
%token <std::string> CADDRESS       "address value"
%token <std::string> CPORT          "port value"
%token <double>      CUREAL         "real value"
%token <uint64_t>    CUINTEGER      "unsigned integer value"
%token <bool>        CBOOL          "bool value"

%token EOD 0 "<end of input>"

%token ADD "add"
%token ASSERT "assert"
%token ASSERT_EXCEPTION "assert-exception"
%token ADDRESS "addr"
%token AFTER "after"
%token AND "&&"
%token ANY "any"
%token ARROW "->"
%token AUTO "auto"
%token AT "at"
%token BEGIN_ "begin"
%token BITFIELD "bitfield"
%token BOOL "bool"
%token BREAK "break"
%token BYTES "bytes"
%token CADDR "caddr"
%token CALLABLE "callable"
%token CASE "case"
%token CAST "cast"
%token CATCH "catch"
%token CHANNEL "channel"
%token CLASSIFIER "classifier"
%token CNULL "Null"
%token CONST "const"
%token CONTINUE "continue"
%token CONTEXT "context"
%token COPY "copy"
%token DECLARE "declare"
%token DEFAULT "default"
%token DELETE "delete"
%token DIVIDEASSIGN "/="
%token DOLLARDOLLAR "$$"
%token DOTDOT ".."
%token REAL "real"
%token ELSE "else"
%token END_ "end"
%token ENUM "enum"
%token EQ "=="
%token ERROR "error"
%token EXCEPTION "exception"
%token EXPORT "export"
%token EXTERN "extern"
%token EXTERN_NO_SUSPEND "extern-no-suspend"
%token FILE "file"
%token FINALIZE "~finally"
%token FOR "for"
%token FROM "from"
%token FUNCTION "function"
%token GEQ ">="
%token GLOBAL "global"
%token HASATTR "?."
%token HOOK "hook"
%token IF "if"
%token IMPORT "import"
%token IN "in"
%token INIT "init"
%token INOUT "inout"
%token INT "int"
%token INT16 "int16"
%token INT32 "int32"
%token INT64 "int64"
%token INT8 "int8"
%token INTERVAL "interval"
%token INTERVAL_NS "interval_ns"
%token IOSRC "iosrc"
%token ITERATOR "iterator"
%token CONST_ITERATOR "const_iterator"
%token LEQ "<="
%token LIBRARY_TYPE "library type"
%token LIBRARY_TYPE_CONST "const library type"
%token LIST "list"
%token LOCAL "local"
%token MAP "map"
%token MATCH_TOKEN_STATE "match_token_state"
%token METHOD "method"
%token MINUSASSIGN "-="
%token MINUSMINUS "--"
%token MOD "%"
%token MODULE "module"
%token MOVE "move"
%token NEW "new"
%token NEQ "!="
%token NETWORK "net"
%token NOT_IN "!in"
%token OPTIONAL "optional"
%token OR "||"
%token OVERLAY "overlay"
%token PACK "pack"
%token PLUSASSIGN "+="
%token PLUSPLUS "++"
%token PORT "port"
%token POW "**"
%token PREINIT "preinit"
%token PRIVATE "private"
%token PUBLIC "public"
%token STRONG_REF "strong_ref"
%token REGEXP "regexp"
%token RESULT "result"
%token RETURN "return"
%token SCOPE "scope"
%token SET "set"
%token SHIFTLEFT "<<"
%token SHIFTRIGHT ">>"
%token STREAM "stream"
%token STRING "string"
%token STRUCT "struct"
%token SWITCH "switch"
%token TIME "time"
%token TIME_NS "time_ns"
%token TIMER "timer"
%token TIMERMGR "timer_mgr"
%token TIMESASSIGN "*="
%token THROW "throw"
%token TRY "try"
%token TRYATTR ".?"
%token TUPLE "tuple"
%token TYPE "type"
%token TYPEINFO "typeinfo"
%token UINT "uint"
%token UINT16 "uint16"
%token UINT32 "uint32"
%token UINT64 "uint64"
%token UINT8 "uint8"
%token UNION "union"
%token UNPACK "unpack"
%token UNSET "unset"
%token VECTOR "vector"
%token VIEW "view"
%token VOID "void"
%token WHILE "while"
%token WITH "with"
%token VALUE_REF "value_ref"
%token WEAK_REF "weak_ref"
%token YIELD "yield"

%type <hilti::ID>                             local_id scoped_id dotted_id function_id scoped_function_id
%type <hilti::Declaration*>                   local_decl local_init_decl global_decl type_decl import_decl constant_decl function_decl global_scope_decl property_decl struct_field union_field
%type <hilti::Declarations>                     struct_fields union_fields opt_union_fields
%type <hilti::UnqualifiedType*>               base_type_no_attrs base_type type function_type tuple_type struct_type enum_type union_type func_param_type bitfield_type
%type <hilti::QualifiedType*>                 qtype
%type <hilti::Ctor*>                          ctor tuple struct_ list regexp map set
%type <hilti::Expression*>                    expr tuple_elem tuple_expr member_expr ctor_expr expr_or_error expr_1 opt_func_default_expr expr_no_or_error call_expr
%type <hilti::Expressions>                      opt_tuple_elems1 opt_tuple_elems2 exprs opt_exprs opt_type_arguments case_exprs
%type <hilti::Function*>                      function_with_body method_with_body hook_with_body function_without_body
%type <hilti::type::function::Parameter*>     func_param
%type <hilti::parameter::Kind>                  opt_func_param_kind
%type <hilti::type::function::Flavor>           func_flavor opt_func_flavor
%type <hilti::type::function::CallingConvention> opt_func_cc
%type <hilti::declaration::Linkage>             opt_linkage
%type <hilti::type::function::Parameters>       func_params opt_func_params opt_struct_params
%type <hilti::Statement*>                     stmt stmt_decl stmt_expr opt_else_block
%type <hilti::statement::Block*>              block braced_block
%type <hilti::Statements>                       stmts opt_stmts
%type <hilti::Attribute*>                     attribute
%type <hilti::AttributeSet*>                  opt_attributes
%type <hilti::type::tuple::Element*>          tuple_type_elem
%type <hilti::type::tuple::Elements>            tuple_type_elems
%type <hilti::ctor::struct_::Fields>            struct_elems
%type <hilti::ctor::struct_::Field*>          struct_elem
%type <hilti::ctor::map::Elements>              map_elems opt_map_elems
%type <hilti::ctor::map::Element*>            map_elem
%type <hilti::type::enum_::Label*>            enum_label
%type <hilti::type::enum_::Labels>              enum_labels
%type <hilti::type::bitfield::BitRanges>        bitfield_bit_ranges opt_bitfield_bit_ranges
%type <hilti::type::bitfield::BitRange*>      bitfield_bit_range
%type <hilti::ctor::regexp::Patterns> re_patterns
%type <hilti::ctor::regexp::Pattern>        re_pattern_constant opt_re_pattern_constant_flags
%type <hilti::statement::switch_::Case*>      switch_case
%type <hilti::statement::switch_::Cases>        switch_cases opt_switch_cases
%type <hilti::statement::try_::Catch*>        try_catch
%type <hilti::statement::try_::Catches>         try_catches

%type <std::pair<Declarations, Statements>>     global_scope_items

%left '=' MINUSASSIGN PLUSASSIGN TIMESASSIGN DIVIDEASSIGN
%left '?' ':'
%left OR
%left AND
%left IN NOT_IN
%left EQ NEQ
%left '<' '>' GEQ LEQ
%left '|'
%left '^'
%left '&'
%left SHIFTLEFT SHIFTRIGHT
%left '+' '-'
%left '%' '*' '/'
%right POW
%right UNARY_PREC MINUSMINUS PLUSPLUS
%left '.' '[' HASATTR TRYATTR

%%

%start module;

module        : MODULE local_id '{'
                global_scope_items '}'           { auto uid = declaration::module::UID($2, hilti::rt::filesystem::path(*driver->currentFile()));
                                                   auto m = builder->declarationModule(uid, {}, std::move($4.first), std::move($4.second), __loc__);
                                                   driver->setDestinationModule(std::move(m));
                                                 }
              ;

/* IDs */

local_id      : IDENT                            { std::string name($1);

                                                   if ( ! driver->builder()->options().skip_validation ) {
                                                       if ( name.find('-') != std::string::npos )
                                                           hilti::logger().error(util::fmt("Invalid ID '%s': cannot contain '-'", name), __loc__.location());

                                                       if ( name.substr(0, 2) == "__" && name != "__hook_to_string" )
                                                           hilti::logger().error(util::fmt("Invalid ID '%s': cannot start with '__'", name), __loc__.location());

                                                       const auto prefix_local = HILTI_INTERNAL_ID("");
                                                       if ( name.starts_with(prefix_local) && name != HILTI_INTERNAL_ID("hook_to_string") )
                                                           hilti::logger().error(hilti::util::fmt("Invalid ID '%s': cannot start with '%s'", name, prefix_local), __loc__.location());

                                                       if ( name.starts_with(HILTI_INTERNAL_NS_ID) )
                                                           hilti::logger().error(hilti::util::fmt("Invalid ID '%s': cannot start with '%s'", name, HILTI_INTERNAL_NS_ID), __loc__.location());
                                                   }

                                                   $$ = hilti::ID(std::move(name));
                                                 }

scoped_id     : local_id                         { $$ = std::move($1); }
              | SCOPED_IDENT                     { $$ = hilti::ID($1); }

dotted_id     : { driver->enableDottedIDMode(); }
                DOTTED_IDENT
                { driver->disableDottedIDMode(); } { $$ = hilti::ID($2); }

/* Declarations */

global_scope_items
              : global_scope_items global_scope_decl
                                                 { $$ = std::move($1); $$.first.push_back($2); }
              | global_scope_items stmt
                                                 { $$ = std::move($1); $$.second.push_back($2); }
              | /* empty */                      { $$ = {}; }
              ;

global_scope_decl
              : type_decl                        { $$ = std::move($1); }
              | constant_decl                    { $$ = std::move($1); }
              | global_decl                      { $$ = std::move($1); }
              | function_decl                    { $$ = std::move($1); }
              | import_decl                      { $$ = std::move($1); }
              | property_decl                    { $$ = std::move($1); }

type_decl     : opt_linkage TYPE scoped_id '=' qtype opt_attributes ';'
                                                 { $$ = builder->declarationType(std::move($3), std::move($5), std::move($6), std::move($1), __loc__); }

constant_decl : opt_linkage CONST scoped_id '=' expr ';'
                                                 { $$ = builder->declarationConstant($3, $5, $1, __loc__); }
              | opt_linkage CONST type scoped_id '=' expr ';'
                                                 { $$ = builder->declarationConstant($4, builder->qualifiedType($3, Constness::Const), $6, $1, __loc__); }
              ;

local_decl    : LOCAL local_id '=' expr ';'     { $$ = builder->declarationLocalVariable($2, $4, __loc__); }
              | LOCAL qtype local_id opt_type_arguments ';' { $$ = builder->declarationLocalVariable($3, $2, $4, {}, __loc__); }
              | LOCAL qtype local_id '=' expr ';'
                                                 { $$ = builder->declarationLocalVariable($3, $2, $5, __loc__); }
              | LOCAL AUTO local_id '=' expr ';'
                                                 { $$ = builder->declarationLocalVariable($3, $5, __loc__); }
              ;

local_init_decl
              : LOCAL qtype local_id '=' expr
                                                 { $$ = builder->declarationLocalVariable($3, $2, $5, __loc__); }
              | LOCAL AUTO local_id '=' expr
                                                 { $$ = builder->declarationLocalVariable($3, $5, __loc__); }
              ;

global_decl   : opt_linkage GLOBAL scoped_id '=' expr ';'
                                                 { $$ = builder->declarationGlobalVariable($3, $5, $1, __loc__); }
              | opt_linkage GLOBAL qtype scoped_id opt_type_arguments ';'
                                                 { $$ = builder->declarationGlobalVariable($4, $3, $5, {}, $1, __loc__); }
              | opt_linkage GLOBAL qtype scoped_id '=' expr ';'
                                                 { $$ = builder->declarationGlobalVariable($4, $3, $6, $1, __loc__); }
              | opt_linkage GLOBAL AUTO scoped_id '=' expr ';'
                                                 { $$ = builder->declarationGlobalVariable($4, $6, $1, __loc__); }
              ;

opt_type_arguments
              : '(' opt_exprs ')'                { $$ = std::move($2); }
              | /* empty */                      { $$ = hilti::Expressions{}; }

function_decl : opt_linkage FUNCTION function_with_body
                                                 { $$ = builder->declarationFunction($3, $1, __loc__); }
              | opt_linkage HOOK hook_with_body              { $$ = builder->declarationFunction($3, $1, __loc__); }


              | METHOD method_with_body          { $$ = builder->declarationFunction($2, hilti::declaration::Linkage::Struct, __loc__); }
              | DECLARE opt_linkage function_without_body ';'
                                                 { $$ = builder->declarationFunction($3, $2, __loc__); }
              ;

import_decl   : IMPORT local_id ';'              { $$ = builder->declarationImportedModule(std::move($2), std::string(".hlt"), __loc__); }
              | IMPORT local_id FROM dotted_id ';' { $$ = builder->declarationImportedModule(std::move($2), std::string(".hlt"), std::move($4), __loc__); }
              ;


property_decl : PROPERTY ';'                     { $$ = builder->declarationProperty(ID(std::move($1)), __loc__); }
              | PROPERTY '=' expr ';'            { $$ = builder->declarationProperty(ID(std::move($1)), std::move($3), __loc__); }

opt_linkage   : PUBLIC                           { $$ = hilti::declaration::Linkage::Public; }
              | PRIVATE                          { $$ = hilti::declaration::Linkage::Private; }
              | INIT                             { $$ = hilti::declaration::Linkage::Init; }
              | PREINIT                          { $$ = hilti::declaration::Linkage::PreInit; }
              | /* empty */                      { $$ = hilti::declaration::Linkage::Private; }

/* Functions */

function_id   : local_id                         { $$ = std::move($1); }
              | FINALIZE                         { $$ = hilti::ID("~finally"); }

scoped_function_id:
                function_id                      { $$ = std::move($1); }
              | SCOPED_IDENT                     { $$ = hilti::ID($1); }
              | SCOPED_FINALIZE                  { $$ = hilti::ID($1); }

function_with_body
              : opt_func_cc qtype scoped_function_id '(' opt_func_params ')' opt_attributes braced_block
                                                 {
                                                    auto ftype = builder->typeFunction($2, $5, type::function::Flavor::Function, $1, __loc__);
                                                    $$ = builder->function($3, ftype->as<type::Function>(), $8, $7, __loc__);
                                                 }

method_with_body
              : opt_func_cc qtype scoped_function_id '(' opt_func_params ')' opt_attributes braced_block
                                                 {
                                                    auto ftype = builder->typeFunction($2, $5, type::function::Flavor::Method, $1, __loc__);
                                                    $$ = builder->function($3, ftype->as<type::Function>(), $8, $7, __loc__);
                                                 }

hook_with_body
              : opt_func_cc qtype scoped_function_id '(' opt_func_params ')' opt_attributes braced_block
                                                 {
                                                    auto ftype = builder->typeFunction($2, $5, type::function::Flavor::Hook, $1, __loc__);
                                                    $$ = builder->function($3, ftype->as<type::Function>(), $8, $7, __loc__);
                                                 }

function_without_body
              : opt_func_flavor opt_func_cc qtype scoped_function_id '(' opt_func_params ')' opt_attributes
                                                 {
                                                    auto ftype = builder->typeFunction($3, $6, $1, $2, __loc__);
                                                    $$ = builder->function($4, std::move(ftype), {}, $8, __loc__);
                                                 }

opt_func_flavor : func_flavor                    { $$ = $1; }
                | /* empty */                    { $$ = hilti::type::function::Flavor::Function; }

func_flavor     : METHOD                         { $$ = hilti::type::function::Flavor::Method; }
                | HOOK                           { $$ = hilti::type::function::Flavor::Hook; }

opt_func_cc     : EXTERN                         { $$ = hilti::type::function::CallingConvention::Extern; }
                | EXTERN_NO_SUSPEND              { $$ = hilti::type::function::CallingConvention::ExternNoSuspend; }
                | /* empty */                    { $$ = hilti::type::function::CallingConvention::Standard; }

opt_func_params : func_params                    { $$ = std::move($1); }
               | /* empty */                     { $$ = hilti::type::function::Parameters(); }

func_params : func_params ',' func_param { $$ = std::move($1); $$.push_back($3); }
                | func_param                     { $$ = hilti::type::function::Parameters{$1}; }

func_param      : opt_func_param_kind func_param_type local_id opt_func_default_expr opt_attributes
                                                 { $$ = builder->declarationParameter($3, $2, $1, $4, $5, __loc__); }
                ;

func_param_type : type                           { $$ = std::move($1); }
                | AUTO                           { $$ = builder->typeAuto(__loc__); }
                ;

opt_func_param_kind
              : COPY                             { $$ = hilti::parameter::Kind::Copy; }
              | INOUT                            { $$ = hilti::parameter::Kind::InOut; }
              | /* empty */                      { $$ = hilti::parameter::Kind::In; }
              ;

opt_func_default_expr : '=' expr                 { $$ = std::move($2); }
              | /* empty */                      { $$ = {}; }
              ;

/* Statements */

block         : stmt                             {
                                                   if ( auto* block = $1->tryAs<hilti::statement::Block>() )
                                                       $$ = std::move(block);
                                                   else
                                                       $$ = builder->statementBlock({std::move($1)}, __loc__);
                                                 }
              ;

braced_block  : '{' opt_stmts '}'                { $$ = builder->statementBlock(std::move($2), __loc__); }

opt_stmts     : stmts                            { $$ = std::move($1); }
              | /* empty */                      { $$ = hilti::Statements(); }

stmts         : stmts stmt                       { $$ = std::move($1); $$.push_back($2); }
              | stmt                             { $$ = hilti::Statements{std::move($1)}; }

stmt          : stmt_expr ';'                    { $$ = std::move($1); }
              | stmt_decl                        { $$ = std::move($1); }
              | braced_block                     { $$ = std::move($1); }
              | RETURN ';'                       { $$ = builder->statementReturn(__loc__); }
              | RETURN expr ';'                  { $$ = builder->statementReturn(std::move($2), __loc__); }
              | THROW expr ';'                   { $$ = builder->statementThrow(std::move($2), __loc__); }
              | THROW  ';'                       { $$ = builder->statementThrow(__loc__); }
              | YIELD ';'                        { $$ = builder->statementYield(__loc__); }
              | BREAK ';'                        { $$ = builder->statementBreak(__loc__); }
              | CONTINUE ';'                     { $$ = builder->statementContinue(__loc__); }
              | IF '(' expr ')' block opt_else_block
                                                 { $$ = builder->statementIf(std::move($3), std::move($5), std::move($6), __loc__); }
              | IF '(' local_init_decl ')' block opt_else_block
                                                 { $$ = builder->statementIf(std::move($3), {}, std::move($5), std::move($6), __loc__); }
              | IF '(' local_init_decl ';' expr ')' block opt_else_block
                                                 { $$ = builder->statementIf(std::move($3), std::move($5), std::move($7), std::move($8), __loc__); }
              | WHILE '(' local_init_decl ';' expr ')' block opt_else_block
                                                 { $$ = builder->statementWhile(std::move($3), std::move($5), std::move($7), std::move($8), __loc__); }
              | WHILE '(' expr ')' block opt_else_block
                                                 { $$ = builder->statementWhile(std::move($3), std::move($5), std::move($6), __loc__); }
              | WHILE '(' local_init_decl ')' block opt_else_block
                                                 { $$ = builder->statementWhile(std::move($3), {}, std::move($5), std::move($6), __loc__); }
              | FOR '(' local_id IN expr ')' block
                                                 { $$ = builder->statementFor(std::move($3), std::move($5), std::move($7), __loc__); }
              | SWITCH '(' expr ')' '{' opt_switch_cases '}'
                                                 { $$ = builder->statementSwitch(std::move($3), std::move($6), __loc__); }
              | SWITCH '(' local_init_decl ')' '{' opt_switch_cases '}'
                                                 { $$ = builder->statementSwitch(std::move($3), std::move($6), __loc__); }
              | TRY block try_catches
                                                 { $$ = builder->statementTry(std::move($2), std::move($3), __loc__); }
              | ASSERT expr ';'                  { $$ = builder->statementAssert(std::move($2), {}, __loc__); }
              | ASSERT_EXCEPTION expr_no_or_error ':' expr ';'
                                                 { $$ = builder->statementAssert(hilti::statement::assert::Exception(), std::move($2), {}, std::move($4), __loc__); }
              | ASSERT_EXCEPTION expr_no_or_error ';'
                                                 { $$ = builder->statementAssert(hilti::statement::assert::Exception(), std::move($2), {}, {}, __loc__); }

              | ADD expr ';'                     { auto op = $2->tryAs<hilti::expression::UnresolvedOperator>();
                                                   if ( ! (op && op->kind() == hilti::operator_::Kind::Index) )
                                                        error(@$, "'add' must be used with index expression only");

                                                   auto expr = builder->expressionUnresolvedOperator(hilti::operator_::Kind::Add, op->operands(), __loc__);
                                                   $$ = builder->statementExpression(std::move(expr), __loc__);
                                                 }

              | DELETE expr ';'                  { auto op = $2->tryAs<hilti::expression::UnresolvedOperator>();
                                                   if ( ! (op && op->kind() == hilti::operator_::Kind::Index) )
                                                        error(@$, "'delete' must be used with index expressions only");

                                                   auto expr = builder->expressionUnresolvedOperator(hilti::operator_::Kind::Delete, op->operands(), __loc__);
                                                   $$ = builder->statementExpression(std::move(expr), __loc__);
                                                 }

              | UNSET expr ';'                   { auto op = $2->tryAs<hilti::expression::UnresolvedOperator>();
                                                   if ( ! (op && op->kind() == hilti::operator_::Kind::Member) )
                                                        error(@$, "'unset' must be used with member expressions only");

                                                   auto expr = builder->expressionUnresolvedOperator(hilti::operator_::Kind::Unset, op->operands(), __loc__);
                                                   $$ = builder->statementExpression(std::move(expr), __loc__);
                                                 }
;

opt_else_block
              : ELSE block                       { $$ = std::move($2); }
              | /* empty */                      { $$ = {}; }

opt_switch_cases
              : switch_cases                     { $$ = std::move($1); }
              | /* empty */                      { $$ = {}; }

switch_cases  : switch_cases switch_case         { $$ = std::move($1); $$.push_back(std::move($2)); }
              | switch_case                      { $$ = hilti::statement::switch_::Cases({std::move($1)}); }

switch_case   : CASE case_exprs ':' block             { $$ = builder->statementSwitchCase(std::move($2), std::move($4), __loc__); }
              | DEFAULT ':' block                { $$ = builder->statementSwitchCase(hilti::statement::switch_::Default(), std::move($3), __loc__); }

case_exprs    : case_exprs ',' expr_no_or_error  { $$ = std::move($1); $$.push_back(std::move($3)); }
              | expr_no_or_error                 { $$ = hilti::Expressions{std::move($1)}; }

try_catches   : try_catches try_catch            { $$ = std::move($1); $$.push_back(std::move($2)); }
              | try_catch                        { $$ = hilti::statement::try_::Catches({ std::move($1) }); }

try_catch     : CATCH '(' func_param_type local_id ')' block
                                                 { $$ = builder->statementTryCatch(builder->declarationParameter($4, $3, parameter::Kind::In, {}, {}, __loc__), std::move($6), __loc__); }
              | CATCH block                      { $$ = builder->statementTryCatch(std::move($2), __loc__); }

stmt_decl     : local_decl                       { $$ = builder->statementDeclaration($1, __loc__); }
              | type_decl                        { $$ = builder->statementDeclaration($1, __loc__); }
              | constant_decl                    { $$ = builder->statementDeclaration($1, __loc__); }
              ;

stmt_expr     : expr                             { $$ = builder->statementExpression($1, __loc__); }

/* Types */

base_type_no_attrs
              : ANY                              { $$ = builder->typeAny(__loc__); }
              | ADDRESS                          { $$ = builder->typeAddress(__loc__); }
              | BOOL                             { $$ = builder->typeBool(__loc__); }
              | BYTES                            { $$ = builder->typeBytes(__loc__); }
              | ERROR                            { $$ = builder->typeError(__loc__); }
              | INTERVAL                         { $$ = builder->typeInterval(__loc__); }
              | NETWORK                          { $$ = builder->typeNetwork(__loc__); }
              | PORT                             { $$ = builder->typePort(__loc__); }
              | REAL                             { $$ = builder->typeReal(__loc__); }
              | REGEXP                           { $$ = builder->typeRegExp(__loc__); }
              | STREAM                           { $$ = builder->typeStream(__loc__); }
              | STRING                           { $$ = builder->typeString(__loc__); }
              | TIME                             { $$ = builder->typeTime(__loc__); }
              | TYPE                             { $$ = builder->typeTypeInfo(__loc__); }
              | VOID                             { $$ = builder->typeVoid(__loc__); }

              | INT type_param_begin CUINTEGER type_param_end            { $$ = builder->typeSignedInteger($3, __loc__); }
              | INT type_param_begin '*' type_param_end                  { $$ = builder->typeSignedInteger(hilti::type::Wildcard(), __loc__); }
              | UINT type_param_begin CUINTEGER type_param_end           { $$ = builder->typeUnsignedInteger($3, __loc__); }
              | UINT type_param_begin '*' type_param_end                 { $$ = builder->typeUnsignedInteger(hilti::type::Wildcard(), __loc__); }

              | OPTIONAL type_param_begin qtype type_param_end           { $$ = builder->typeOptional($3, __loc__); }
              | RESULT type_param_begin qtype type_param_end             { $$ = builder->typeResult($3, __loc__); }
              | VIEW type_param_begin qtype type_param_end               { $$ = viewForType(builder, std::move($3), __loc__)->type(); }
              | ITERATOR type_param_begin qtype type_param_end           { $$ = iteratorForType(builder, std::move($3), __loc__)->type(); }
              | STRONG_REF type_param_begin qtype type_param_end         { $$ = builder->typeStrongReference($3, __loc__); }
              | STRONG_REF type_param_begin '*' type_param_end           { $$ = builder->typeStrongReference(hilti::type::Wildcard(), __loc__); }
              | VALUE_REF type_param_begin qtype type_param_end          { $$ = builder->typeValueReference($3, __loc__); }
              | VALUE_REF type_param_begin '*' type_param_end            { $$ = builder->typeValueReference(hilti::type::Wildcard(), __loc__); }
              | WEAK_REF type_param_begin qtype type_param_end           { $$ = builder->typeWeakReference($3, __loc__); }
              | WEAK_REF type_param_begin '*' type_param_end             { $$ = builder->typeWeakReference(hilti::type::Wildcard(), __loc__); }

              | LIST type_param_begin '*' type_param_end                 { $$ = builder->typeList(hilti::type::Wildcard(), __loc__); }
              | LIST type_param_begin qtype type_param_end               { $$ = builder->typeList(std::move($3), __loc__); }
              | VECTOR type_param_begin '*' type_param_end               { $$ = builder->typeVector(hilti::type::Wildcard(), __loc__); }
              | VECTOR type_param_begin qtype type_param_end             { $$ = builder->typeVector(std::move($3), __loc__); }
              | SET type_param_begin '*' type_param_end                  { $$ = builder->typeSet(hilti::type::Wildcard(), __loc__); }
              | SET type_param_begin qtype type_param_end                { $$ = builder->typeSet(std::move($3), __loc__); }
              | MAP type_param_begin '*' type_param_end                  { $$ = builder->typeMap(hilti::type::Wildcard(), __loc__); }
              | MAP type_param_begin qtype ',' qtype type_param_end      { $$ = builder->typeMap(std::move($3), std::move($5), __loc__); }

              | EXCEPTION                        { $$ = builder->typeException(__loc__); }
              | '[' EXCEPTION ':' type ']'       { $$ = builder->typeException(std::move($4), __loc__); }

              | LIBRARY_TYPE '(' CSTRING ')'     { $$ = builder->typeLibrary(std::move($3), __loc__); }
              | LIBRARY_TYPE_CONST '(' CSTRING ')'
                                                 { $$ = builder->typeLibrary(Constness::Const, std::move($3), __loc__); }

              | tuple_type                       { $$ = std::move($1); }
              | struct_type                      { $$ = std::move($1); }
              | union_type                       { $$ = std::move($1); }
              | enum_type                        { $$ = std::move($1); }
              | bitfield_type                    { $$ = std::move($1); }
              ;

base_type     : base_type_no_attrs               { $$ = $1; }
              ;

type          : base_type                        { $$ = std::move($1); }
              | function_type                    { $$ = std::move($1); }
              | scoped_id                        { $$ = builder->typeName(std::move($1), __loc__); }
              ;

qtype         : type                             { $$ = builder->qualifiedType(std::move($1), Constness::Mutable, __loc__); }
              | CONST type                       { $$ = builder->qualifiedType(std::move($2), Constness::Const, __loc__); }
              | AUTO                             { $$ = builder->qualifiedType(builder->typeAuto(__loc__), Constness::Const, __loc__); }
              ;

type_param_begin:
              '<'
              { driver->disableExpressionMode(); }

type_param_end:
              '>'
              { driver->enableExpressionMode(); }

function_type : opt_func_flavor FUNCTION '(' opt_func_params ')' ARROW qtype
                                                 { $$ = builder->typeFunction($7, $4, $1, type::function::CallingConvention::Standard, __loc__); }
              ;

tuple_type    : TUPLE type_param_begin '*' type_param_end                { $$ = builder->typeTuple(hilti::type::Wildcard(), __loc__); }
              | TUPLE type_param_begin tuple_type_elems type_param_end   { $$ = builder->typeTuple(std::move($3), __loc__); }
              ;

tuple_type_elems
              : tuple_type_elems ',' tuple_type_elem
                                                 { $$ = std::move($1); $$.push_back(std::move($3)); }
              | tuple_type_elem                  { $$ = hilti::type::tuple::Elements{std::move($1)}; }
              ;

tuple_type_elem
              : qtype                             { $$ = builder->typeTupleElement(hilti::ID(), std::move($1), __loc__); }
              | local_id ':' qtype                { $$ = builder->typeTupleElement(std::move($1), std::move($3), __loc__); }
              ;

struct_type   : STRUCT opt_struct_params '{' struct_fields '}'     { $$ = builder->typeStruct(std::move($2), std::move($4), __loc__); }

opt_struct_params
              : '(' opt_func_params ')'          { $$ = std::move($2); }
              | /* empty */                      { $$ = hilti::type::function::Parameters{}; }

struct_fields : struct_fields struct_field       { $$ = std::move($1); $$.push_back($2); }
              | /* empty */                      { $$ = hilti::Declarations{}; }

struct_field  : qtype local_id opt_attributes ';' { $$ = builder->declarationField(std::move($2), std::move($1), std::move($3), __loc__); }
              | func_flavor opt_func_cc qtype function_id '(' opt_func_params ')' opt_attributes ';' {
                                                   auto ftype = builder->typeFunction(std::move($3), std::move($6), $1, $2, __loc__);
                                                   $$ = builder->declarationField(std::move($4), std::move(ftype), $8, __loc__);
                                                   }
              | func_flavor opt_func_cc qtype function_id '(' opt_func_params ')' opt_attributes braced_block {
                                                   auto ftype = builder->typeFunction(std::move($3), std::move($6), $1, $2, __loc__);
                                                   auto func = builder->function($4, std::move(ftype), std::move($9), {});
                                                   $$ = builder->declarationField($4, std::move(func), $8, __loc__);
                                                   }

union_type    : UNION opt_attributes'{' opt_union_fields '}'
                                                 { $$ = builder->typeUnion(std::move($4), __loc__); }

opt_union_fields : union_fields                  { $$ = $1; }
              | /* empty */                      { $$ = hilti::Declarations{}; }

union_fields  : union_fields ',' union_field     { $$ = std::move($1); $$.push_back(std::move($3)); }
              | union_field                      { $$ = hilti::Declarations{}; $$.push_back(std::move($1)); }

union_field  : qtype local_id opt_attributes      { $$ = builder->declarationField(std::move($2), std::move($1), std::move($3), __loc__); }

enum_type     : ENUM '{' enum_labels '}'         { $$ = builder->typeEnum(std::move($3), __loc__); }
              | ENUM '<' '*' '>'                 { $$ = builder->typeEnum(type::Wildcard(), __loc__); }

enum_labels   : enum_labels ',' enum_label       { $$ = std::move($1); $$.push_back(std::move($3)); }
              | enum_labels ','                  { $$ = std::move($1); }
              | enum_label                       { $$ = hilti::type::enum_::Labels(); $$.push_back(std::move($1)); }
              ;

enum_label    : local_id                         { $$ = builder->typeEnumLabel(std::move($1), __loc__); }
              | local_id '=' CUINTEGER           { $$ = builder->typeEnumLabel(std::move($1), $3, __loc__); }
              ;

bitfield_type : BITFIELD '(' CUINTEGER ')'
                                                 { _field_width = $3; }
                '{' opt_bitfield_bit_ranges '}'
                                                 { $$ = builder->typeBitfield($3, $7, {}, __loc__); }

opt_bitfield_bit_ranges
              : bitfield_bit_ranges
                                                 { $$ = std::move($1); }
              | /* empty */                      { $$ = type::bitfield::BitRanges(); }

bitfield_bit_ranges
              : bitfield_bit_ranges bitfield_bit_range
                                                 { $$ = std::move($1); $$.push_back(std::move($2));  }
              | bitfield_bit_range               { $$ = type::bitfield::BitRanges(); $$.push_back(std::move($1)); }

bitfield_bit_range
              : local_id ':' CUINTEGER DOTDOT CUINTEGER opt_attributes ';'
                                                 { $$ = builder->typeBitfieldBitRange(std::move($1), $3, $5, _field_width, std::move($6), __loc__); }
              | local_id ':' CUINTEGER opt_attributes ';'
                                                 { $$ = builder->typeBitfieldBitRange(std::move($1), $3, $3, _field_width, std::move($4), __loc__); }
/* Expressions */

expr          : expr_or_error                    { $$ = std::move($1); }
              ;

expr_no_or_error
              : expr_1                           { $$ = std::move($1); }

opt_exprs     : exprs                            { $$ = std::move($1); }
              | /* empty */                      { $$ = hilti::Expressions(); }

exprs         : exprs ',' expr                   { $$ = std::move($1); $$.push_back(std::move($3)); }
              | expr                             { $$ = hilti::Expressions{std::move($1)}; }

expr_or_error : expr_1                           { $$ = std::move($1); }
              | expr_1 ':' expr                  { $$ = builder->expressionConditionTest(std::move($1), std::move($3), __loc__); }
              ;

expr_1        : expr_1 '=' expr_1                { $$ = builder->expressionAssign(std::move($1), std::move($3), __loc__); }
              | expr_1 MINUSASSIGN expr_1        { $$ = builder->expressionUnresolvedOperator(hilti::operator_::Kind::DifferenceAssign, {std::move($1), std::move($3)}, __loc__); }
              | expr_1 PLUSASSIGN expr_1         { $$ = builder->expressionUnresolvedOperator(hilti::operator_::Kind::SumAssign, {std::move($1), std::move($3)}, __loc__); }
              | expr_1 TIMESASSIGN expr_1        { $$ = builder->expressionUnresolvedOperator(hilti::operator_::Kind::MultipleAssign, {std::move($1), std::move($3)}, __loc__); }
              | expr_1 DIVIDEASSIGN expr_1       { $$ = builder->expressionUnresolvedOperator(hilti::operator_::Kind::DivisionAssign, {std::move($1), std::move($3)}, __loc__); }
              | expr_1 '?' expr_1 ':' expr_1     { $$ = builder->expressionTernary(std::move($1), std::move($3), std::move($5), __loc__); }
              | expr_1 OR expr_1                 { $$ = builder->expressionLogicalOr(std::move($1), std::move($3), __loc__); }
              | expr_1 AND expr_1                { $$ = builder->expressionLogicalAnd(std::move($1), std::move($3), __loc__); }
              | expr_1 EQ expr_1                 { $$ = builder->expressionUnresolvedOperator(hilti::operator_::Kind::Equal, {std::move($1), std::move($3)}, __loc__); }
              | expr_1 NEQ expr_1                { $$ = builder->expressionUnresolvedOperator(hilti::operator_::Kind::Unequal, {std::move($1), std::move($3)}, __loc__); }
              | expr_1 '<' expr_1                { $$ = builder->expressionUnresolvedOperator(hilti::operator_::Kind::Lower, {std::move($1), std::move($3)}, __loc__); }
              | expr_1 '>' expr_1                { $$ = builder->expressionUnresolvedOperator(hilti::operator_::Kind::Greater, {std::move($1), std::move($3)}, __loc__); }
              | expr_1 GEQ expr_1                { $$ = builder->expressionUnresolvedOperator(hilti::operator_::Kind::GreaterEqual, {std::move($1), std::move($3)}, __loc__); }
              | expr_1 LEQ expr_1                { $$ = builder->expressionUnresolvedOperator(hilti::operator_::Kind::LowerEqual, {std::move($1), std::move($3)}, __loc__); }
              | expr_1 '|' expr_1                { $$ = builder->expressionUnresolvedOperator(hilti::operator_::Kind::BitOr, {std::move($1), std::move($3)}, __loc__); }
              | expr_1 '^' expr_1                { $$ = builder->expressionUnresolvedOperator(hilti::operator_::Kind::BitXor, {std::move($1), std::move($3)}, __loc__); }
              | expr_1 '&' expr_1                { $$ = builder->expressionUnresolvedOperator(hilti::operator_::Kind::BitAnd, {std::move($1), std::move($3)}, __loc__); }
              | expr_1 SHIFTLEFT expr_1          { $$ = builder->expressionUnresolvedOperator(hilti::operator_::Kind::ShiftLeft, {std::move($1), std::move($3)}, __loc__); }
              | expr_1 SHIFTRIGHT expr_1         { $$ = builder->expressionUnresolvedOperator(hilti::operator_::Kind::ShiftRight, {std::move($1), std::move($3)}, __loc__); }
              | expr_1 '+' expr_1                { $$ = builder->expressionUnresolvedOperator(hilti::operator_::Kind::Sum, {std::move($1), std::move($3)}, __loc__); }
              | expr_1 '-' expr_1                { $$ = builder->expressionUnresolvedOperator(hilti::operator_::Kind::Difference, {std::move($1), std::move($3)}, __loc__); }
              | expr_1 '%' expr_1                { $$ = builder->expressionUnresolvedOperator(hilti::operator_::Kind::Modulo, {std::move($1), std::move($3)}, __loc__); }
              | expr_1 '*' expr_1                { $$ = builder->expressionUnresolvedOperator(hilti::operator_::Kind::Multiple, {std::move($1), std::move($3)}, __loc__); }
              | expr_1 '/' expr_1                { $$ = builder->expressionUnresolvedOperator(hilti::operator_::Kind::Division, {std::move($1), std::move($3)}, __loc__); }
              | expr_1 POW expr_1                { $$ = builder->expressionUnresolvedOperator(hilti::operator_::Kind::Power, {std::move($1), std::move($3)}, __loc__); }
              | '!' expr_1 %prec UNARY_PREC      { $$ = builder->expressionLogicalNot(std::move($2), __loc__); }
              | '*' expr_1 %prec UNARY_PREC      { $$ = builder->expressionUnresolvedOperator(hilti::operator_::Kind::Deref, {std::move($2)}, __loc__); }
              | '~' expr_1 %prec UNARY_PREC      { $$ = builder->expressionUnresolvedOperator(hilti::operator_::Kind::Negate, {std::move($2)}, __loc__); }
              | '-' expr_1 %prec UNARY_PREC      { $$ = builder->expressionUnresolvedOperator(hilti::operator_::Kind::SignNeg, {std::move($2)}, __loc__); }
              | '|' expr_1 '|' %prec UNARY_PREC  { $$ = builder->expressionUnresolvedOperator(hilti::operator_::Kind::Size, {std::move($2)}, __loc__); }
              | MINUSMINUS expr_1                { $$ = builder->expressionUnresolvedOperator(hilti::operator_::Kind::DecrPrefix, {std::move($2)}, __loc__); }
              | PLUSPLUS expr_1                  { $$ = builder->expressionUnresolvedOperator(hilti::operator_::Kind::IncrPrefix, {std::move($2)}, __loc__); }
              | expr_1 '[' expr ']'              { $$ = builder->expressionUnresolvedOperator(hilti::operator_::Kind::Index, {std::move($1), std::move($3)}, __loc__); }
              | expr_1 '.' member_expr           { $$ = builder->expressionUnresolvedOperator(hilti::operator_::Kind::Member, {std::move($1), std::move($3)}, __loc__); }
              | expr_1 '.' member_expr '(' opt_exprs ')'   { $$ = builder->expressionUnresolvedOperator(hilti::operator_::Kind::MemberCall, {std::move($1), std::move($3), builder->expressionCtor(builder->ctorTuple(std::move($5), __loc__))}, __loc__); }
              | expr_1 MINUSMINUS                { $$ = builder->expressionUnresolvedOperator(hilti::operator_::Kind::DecrPostfix, {std::move($1)}, __loc__); }
              | expr_1 PLUSPLUS                  { $$ = builder->expressionUnresolvedOperator(hilti::operator_::Kind::IncrPostfix, {std::move($1)}, __loc__); }
              | expr_1 HASATTR member_expr       { $$ = builder->expressionUnresolvedOperator(hilti::operator_::Kind::HasMember, {std::move($1), std::move($3)}, __loc__); }
              | expr_1 TRYATTR member_expr       { $$ = builder->expressionUnresolvedOperator(hilti::operator_::Kind::TryMember, {std::move($1), std::move($3)}, __loc__); }
              | expr_1 IN expr_1                 { $$ = builder->expressionUnresolvedOperator(hilti::operator_::Kind::In, {std::move($1), std::move($3)}, __loc__); }
              | expr_1 NOT_IN expr_1             { $$ = builder->expressionLogicalNot(builder->expressionUnresolvedOperator(hilti::operator_::Kind::In, {std::move($1), std::move($3)}, __loc__)); }
              | call_expr                        { $$ = std::move($1); }
              | CAST type_param_begin qtype type_param_end '(' expr ')'   { $$ = builder->expressionUnresolvedOperator(hilti::operator_::Kind::Cast, {std::move($6), builder->expressionType(std::move($3))}, __loc__); }
              | PACK tuple_expr   { $$ = builder->expressionUnresolvedOperator(hilti::operator_::Kind::Pack, {std::move($2)}, __loc__); }
              | UNPACK type_param_begin qtype type_param_end tuple_expr   { $$ = builder->expressionUnresolvedOperator(hilti::operator_::Kind::Unpack, {builder->expressionType(std::move($3)), std::move($5), builder->expressionCtor(builder->ctorBool(false), __loc__)}, __loc__); }
              | BEGIN_ '(' expr ')'              { $$ = builder->expressionUnresolvedOperator(hilti::operator_::Kind::Begin, {std::move($3)}, __loc__); }
              | END_ '(' expr ')'                { $$ = builder->expressionUnresolvedOperator(hilti::operator_::Kind::End, {std::move($3)}, __loc__); }
              | MOVE '(' expr ')'                { $$ = builder->expressionMove(std::move($3), __loc__); }
              | NEW ctor                         { $$ = builder->expressionUnresolvedOperator(hilti::operator_::Kind::New, {builder->expressionCtor(std::move($2), __loc__),             builder->expressionCtor(builder->ctorTuple({}, __loc__))}, __loc__); }
              | NEW qtype                        { $$ = builder->expressionUnresolvedOperator(hilti::operator_::Kind::New, {builder->expressionType(std::move($2)), builder->expressionCtor(builder->ctorTuple({}, __loc__))}, __loc__); }
              | NEW qtype '(' opt_exprs ')'      { $$ = builder->expressionUnresolvedOperator(hilti::operator_::Kind::New, {builder->expressionType(std::move($2)), builder->expressionCtor(builder->ctorTuple(std::move($4), __loc__))}, __loc__); }
              | TYPEINFO '(' expr ')'            { $$ = builder->expressionTypeInfo(std::move($3), __loc__); }
              | TYPEINFO '(' base_type ')'       { $$ = builder->expressionTypeInfo(builder->expressionType(builder->qualifiedType(std::move($3), Constness::Mutable)), __loc__); }
              | ctor                             { $$ = builder->expressionCtor(std::move($1), __loc__); }
              | ctor_expr                        { $$ = std::move($1); }
              | '[' expr FOR local_id IN expr ']'{ $$ = builder->expressionListComprehension(std::move($6), std::move($2), std::move($4), {},  __loc__); }
              | '[' expr FOR local_id IN expr IF expr ']'   { $$ = builder->expressionListComprehension(std::move($6), std::move($2), std::move($4), std::move($8),  __loc__); }
              | '(' expr ')'                     { $$ = builder->expressionGrouping(std::move($2)); }
              | scoped_id                        { $$ = builder->expressionName(std::move($1), __loc__); }
              | DOLLARDOLLAR                     { $$ = builder->expressionName(std::move(HILTI_INTERNAL_ID("dd")), __loc__); }
              | SCOPE                            { $$ = builder->expressionKeyword(hilti::expression::keyword::Kind::Scope, __loc__); }
              ;

call_expr     : expr_1 '(' opt_exprs ')'         { $$ = builder->expressionUnresolvedOperator(hilti::operator_::Kind::Call, {std::move($1), builder->expressionCtor(builder->ctorTuple(std::move($3), __loc__))}, __loc__); }
              ;


member_expr   : local_id                         { $$ = builder->expressionMember(std::move($1), __loc__); }
              | ERROR                            { $$ = builder->expressionMember(ID("error"), __loc__); } // allow methods of that name even though reserved keyword

/* Constants */

ctor          : CBOOL                            { $$ = builder->ctorBool($1, __loc__); }
              | CBYTES                           { $$ = builder->ctorBytes(std::move($1), __loc__); }
              | CSTRING                          { $$ = builder->ctorString($1, false, __loc__); }
              | CUINTEGER                        { $$ = builder->ctorUnsignedInteger($1, 64, __loc__); }
              | '+' CUINTEGER                    { if ( $2 > static_cast<uint64_t>(std::numeric_limits<int64_t>::max()) )
                                                    logger().error("integer constant out of range", __loc__.location());

                                                   $$ = builder->ctorSignedInteger($2, 64, __loc__);
                                                 }
              | CUREAL                           { $$ = builder->ctorReal($1, __loc__); }
              | '+' CUREAL                       { $$ = builder->ctorReal($2, __loc__);; }
              | CNULL                            { $$ = builder->ctorNull(__loc__); }

              | CADDRESS                         { $$ = builder->ctorAddress(hilti::rt::Address($1), __loc__); }
              | CADDRESS '/' CUINTEGER           { $$ = builder->ctorNetwork(hilti::rt::Network($1, $3), __loc__); }
              | CPORT                            { $$ = builder->ctorPort(hilti::rt::Port($1), __loc__); }

              /* There are more here that we could move into ctor_expr and have them use namedCtor.
                 But not sure if that'd change much so leaving here for now.
              */
              | OPTIONAL '(' expr ')'            { $$ = builder->ctorOptional(std::move($3), __loc__); }
              | DEFAULT type_param_begin type type_param_end '(' opt_exprs ')'
                                                 { $$ = builder->ctorDefault(std::move($3), std::move($6), __loc__); }
              | list                             { $$ = std::move($1); }
              | map                              { $$ = std::move($1); }
              | regexp                           { $$ = std::move($1); }
              | set                              { $$ = std::move($1); }
              | struct_                          { $$ = std::move($1); }
              | tuple                            { $$ = std::move($1); }
              ;

ctor_expr     : INTERVAL '(' expr ')'            { $$ = builder->namedCtor("interval", { std::move($3) }, __loc__); }
              | INTERVAL_NS '(' expr ')'         { $$ = builder->namedCtor("interval_ns", { std::move($3) }, __loc__); }
              | TIME '(' expr ')'                { $$ = builder->namedCtor("time", { std::move($3) }, __loc__); }
              | TIME_NS '(' expr ')'             { $$ = builder->namedCtor("time_ns", { std::move($3) }, __loc__); }
              | STREAM '(' expr ')'              { $$ = builder->namedCtor("stream", { std::move($3) }, __loc__); }
              | ERROR '(' expr ')'               { $$ = builder->namedCtor("error", { std::move($3) }, __loc__); }
              | INT8 '(' expr ')'                { $$ = builder->namedCtor("int8", { std::move($3) }, __loc__); }
              | INT16 '(' expr ')'               { $$ = builder->namedCtor("int16", { std::move($3) }, __loc__); }
              | INT32 '(' expr ')'               { $$ = builder->namedCtor("int32", { std::move($3) }, __loc__); }
              | INT64 '(' expr ')'               { $$ = builder->namedCtor("int64", { std::move($3) }, __loc__); }
              | UINT8 '(' expr ')'               { $$ = builder->namedCtor("uint8", { std::move($3) }, __loc__); }
              | UINT16 '(' expr ')'              { $$ = builder->namedCtor("uint16", { std::move($3) }, __loc__); }
              | UINT32 '(' expr ')'              { $$ = builder->namedCtor("uint32", { std::move($3) }, __loc__); }
              | UINT64 '(' expr ')'              { $$ = builder->namedCtor("uint64", { std::move($3) }, __loc__); }
              | PORT '(' expr ',' expr ')'       { $$ = builder->namedCtor("port", {std::move($3), std::move($5)}, __loc__); }
              ;

tuple         : '(' opt_tuple_elems1 ')'         { $$ = builder->ctorTuple(std::move($2), __loc__); }

opt_tuple_elems1
              : tuple_elem                       { $$ = hilti::Expressions{std::move($1)}; }
              | tuple_elem ',' opt_tuple_elems2  { $$ = hilti::Expressions{std::move($1)}; $$.insert($$.end(), $3.begin(), $3.end()); }
              | /* empty */                      { $$ = hilti::Expressions(); }

opt_tuple_elems2
              : tuple_elem                       { $$ = hilti::Expressions{ std::move($1)}; }
              | tuple_elem ',' opt_tuple_elems2  { $$ = hilti::Expressions{std::move($1)}; $$.insert($$.end(), $3.begin(), $3.end()); }
              | /* empty */                      { $$ = hilti::Expressions(); }


tuple_elem    : expr                             { $$ = std::move($1); }
              ;

tuple_expr    : tuple                            { $$ = builder->expressionCtor(std::move($1), __loc__); }

list          : '[' opt_exprs ']'                { $$ = builder->ctorList(std::move($2), __loc__); }
              | LIST '(' opt_exprs ')'           { $$ = builder->ctorList(std::move($3), __loc__); }
              | LIST type_param_begin qtype type_param_end '(' opt_tuple_elems1 ')'
                                                 { $$ = builder->ctorList(std::move($3), std::move($6), __loc__); }
              | VECTOR '(' opt_exprs ')'         { $$ = builder->ctorVector(std::move($3), __loc__); }
              | VECTOR type_param_begin qtype type_param_end '(' opt_tuple_elems1 ')'
                                                 { $$ = builder->ctorVector(std::move($3), std::move($6), __loc__); }

set           : SET '(' opt_exprs ')'            { $$ = builder->ctorSet(std::move($3), __loc__); }
              | SET type_param_begin qtype type_param_end '(' opt_tuple_elems1 ')'
                                                 { $$ = builder->ctorSet(std::move($3), std::move($6), __loc__); }

map           : MAP '(' opt_map_elems ')'        { $$ = builder->ctorMap(std::move($3), __loc__); }
              | MAP type_param_begin qtype ',' qtype type_param_end '(' opt_map_elems ')'
                                                 { $$ = builder->ctorMap(std::move($3), std::move($5), std::move($8), __loc__); }

struct_       : '[' struct_elems ']'         { $$ = builder->ctorStruct(std::move($2), __loc__); }

struct_elems  : struct_elems ',' struct_elem     { $$ = std::move($1); $$.push_back($3); }
              | struct_elem                      { $$ = hilti::ctor::struct_::Fields{ std::move($1) }; }

struct_elem   : '$' local_id  '=' expr           { $$ = builder->ctorStructField(std::move($2), std::move($4)); }

regexp        : re_patterns opt_attributes       { $$ = builder->ctorRegExp(std::move($1), std::move($2), __loc__); }

re_patterns   : re_patterns '|' re_pattern_constant
                                                 { $$ = $1; $$.push_back(std::move($3)); }
              | re_pattern_constant              { $$ = hilti::ctor::regexp::Patterns{std::move($1)}; }

re_pattern_constant
              : '/' { driver->enablePatternMode(); } CREGEXP { driver->disablePatternMode(); } '/' opt_re_pattern_constant_flags
                                                 {
                                                   $$ = $6;
                                                   $$.setValue($3);
                                                 }

opt_re_pattern_constant_flags
              : local_id opt_re_pattern_constant_flags
                                                 {
                                                   $$ = $2;
                                                   if ( $1 == ID("i") )
                                                       $$.setCaseInsensitive(true);
                                                   else
                                                       error(@$, "unknown regular expression flag");
                                                 }
              | '$' '(' CUINTEGER ')' opt_re_pattern_constant_flags
                                                 {
                                                   $$ = $5;
                                                   $$.setMatchID($3);
                                                 }
              | /* empty */                      { $$ = {}; }

opt_map_elems : map_elems                        { $$ = std::move($1); }
              | /* empty */                      { $$ = hilti::ctor::map::Elements(); }

map_elems     : map_elems ',' map_elem           { $$ = std::move($1); $$.push_back(std::move($3)); }
              | map_elem                         { $$ = hilti::ctor::map::Elements(); $$.push_back(std::move($1)); }

map_elem      : expr_no_or_error ':' expr        { $$ = builder->ctorMapElement($1, $3, __loc__); }


attribute     : ATTRIBUTE                        { try {
                                                       $$ = builder->attribute(hilti::attribute::kind::from_string($1), __loc__);
                                                   } catch ( std::out_of_range& e ) {
                                                       error(@$, hilti::util::fmt("unknown attribute '%s'", $1));
                                                       $$ = nullptr;
                                                   }
                                                 }
              | ATTRIBUTE '=' expr               { try {
                                                       $$ = builder->attribute(hilti::attribute::kind::from_string($1), std::move($3), __loc__);
                                                   } catch ( std::out_of_range& e ) {
                                                       error(@$, hilti::util::fmt("unknown attribute '%s'", $1));
                                                       $$ = nullptr;
                                                   }
                                                 }

opt_attributes
              : opt_attributes attribute        { if ( $2 )
                                                    $1->add(builder->context(), $2);

                                                  $$ = $1;
                                                }
              | /* empty */                     { $$ = builder->attributeSet({}, __loc__); }

%%

void hilti::detail::parser::Parser::error(const Parser::location_type& l, const std::string& m) {
    driver->error(m, toMeta(l));
}
