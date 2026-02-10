/* Copyright (c) 2020-now by the Zeek Project. See LICENSE for details. */

/* This grammar is written against the bison-3.3 API. If an older Bison version
 * was detected we perform preprocessing to support versions down to at least
 * bison-3.0, see the CMake macro `BISON_TARGET_PP`. */
%require "3.3"

%skeleton "lalr1.cc"                          /*  -*- C++ -*- */
%defines

%{
namespace spicy { namespace detail { class Parser; } }

#include <hilti/compiler/context.h>
#include <spicy/compiler/detail/parser/driver.h>
#include <spicy/ast/builder/builder.h>

%}

%locations
%initial-action
{
    @$.begin.filename = @$.end.filename = driver->currentFile();
};

%parse-param {Driver* driver} {Builder* builder}
%lex-param   {Driver* driver}

%define api.namespace {spicy::detail::parser}
%define api.parser.class {Parser}
%define api.value.type variant
%define parse.error verbose

%debug
%verbose

%glr-parser
%expect 134
%expect-rr 174

%{

#include <spicy/compiler/detail/parser/scanner.h>

#undef yylex
#define yylex driver->scanner()->lex

static hilti::Meta toMeta(spicy::detail::parser::location l) {
    return hilti::Meta(hilti::Location(*l.begin.filename, l.begin.line, l.end.line, l.begin.column,
                                       (l.end.column > 0 ? l.end.column - 1 : 0)));
}

static hilti::QualifiedType* iteratorForType(spicy::Builder* builder, hilti::QualifiedType* t, hilti::Meta m) {
    if ( auto iter = t->type()->iteratorType() )
        return iter;
    else {
        hilti::logger().error(hilti::util::fmt("type '%s' is not iterable", *t), m.location());
        return builder->qualifiedType(builder->typeError(), hilti::Constness::Const);
        }
}

static hilti::QualifiedType* viewForType(spicy::Builder* builder, hilti::QualifiedType* t, hilti::Meta m) {
    if ( auto v = t->type()->viewType() )
        return v;
    else {
        hilti::logger().error(hilti::util::fmt("type '%s' is not viewable", *t), m.location());
        return builder->qualifiedType(builder->typeError(), hilti::Constness::Const);
        }
}

/**
 * Checks if an unsigned integer value can be represented as an int64_t.
 *
 * @param x value to check
 * @param positive if false, check if ``-x`` can be represented instead of ``x`` itself.
 * @param m location information to associate with error message.
 * @return *x* on success, or zero on failure as a temporary stand-in; in the
 * latter cases an error is reported, too
 */
static uint64_t check_int64_range(uint64_t x, bool positive, const hilti::Meta& m) {
    uint64_t max = (positive ? std::numeric_limits<int64_t>::max() : std::fabs(std::numeric_limits<int64_t>::min()));
    if ( x <= max )
        return x;

    hilti::logger().error("signed integer value out of range", m.location());
    return 0; // Return dummy value
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

// We keep a stack of doc strings here that's maintained during parsing. There
// would actually be a much nicer way of doing this through Bison's mid-action
// rules, but unfortunately those have a bug with Bison < 3.1 that prevents
// passing results back from a mid-action rule; see
// https://stackoverflow.com/questions/44811550/bison-c-mid-rule-value-lost-with-variants.
//
// Bison 3.1 fixes this and introduces a new, nicer typing syntax for
// mid-action rules as well; see
// https://www.gnu.org/software/bison/manual/html_node/Typed-Mid_002dRule-Actions.html#Typed-Mid_002dRule-Actions
// Unfortunately, we cannot rely on having 3.1 yet, because some of our
// supported platforms do not provide it. Once we can, we should get rid of
// this stack and move to that new syntax instead.
static std::vector<hilti::DocString> _docs;

%}

%token <std::string> IDENT          "identifier"
%token <std::string> SCOPED_IDENT   "scoped identifier"
%token <std::string> DOTTED_IDENT   "dotted identifier"
%token <std::string> HOOK_IDENT     "hook identifier"
%token <std::string> DOLLAR_IDENT   "$-identifier"
%token <std::string> ATTRIBUTE      "attribute"
%token <std::string> PROPERTY       "property"
%token <std::string> PREPROCESSOR   "preprocessor directive"
%token <std::string> CSTRING        "string value"
%token <std::string> CBYTES         "bytes value"
%token <std::string> CERROR         "error value"
%token <std::string> CREGEXP        "regular expression value"
%token <std::string> CADDRESS       "address value"
%token <std::string> CPORT          "port value"

%token <double>    CUREAL         "real value"
%token <uint64_t>  CUINTEGER      "unsigned integer value"
%token <uint64_t>  DOLLAR_NUMBER  "$<N>"
%token <bool>      CBOOL          "bool value"
%token             CNULL          "null value"

%token EOD 0            "<end of input>"
%token ASSERT           "assert"
%token ASSERT_EXCEPTION "assert-exception"
%token ADD
%token ADDRESS
%token AND
%token ANY
%token ARROW
%token AUTO
%token BITFIELD
%token BEGIN_
%token BOOL
%token BREAK
%token BYTES
%token CADDR
%token CASE
%token CAST
%token CATCH
%token CONST
%token CONSTANT
%token CONTINUE
%token DEBUG_
%token DECLARE
%token DEFAULT
%token DELETE
%token DIVIDEASSIGN
%token DOLLARDOLLAR
%token DOTDOT
%token REAL
%token ELSE
%token END_
%token ENUM
%token EQ
%token __ERROR
%token EXCEPTION
%token EXPORT
%token FILE
%token FOR
%token FOREACH
%token FROM
%token FUNCTION
%token GEQ
%token GLOBAL
%token HASATTR
%token HOOK_COMPOSE
%token HOOK_PARSE
%token IF
%token IMPORT
%token IN
%token INOUT
%token INT
%token INT16
%token INT32
%token INT64
%token INT8
%token INTERVAL
%token INTERVAL_NS
%token ITERATOR
%token CONST_ITERATOR
%token LEQ
%token LIBRARY_TYPE
%token LIBRARY_TYPE_CONST
%token LIST
%token LOCAL
%token MAP
%token MARK
%token CAPTURES
%token MINUSASSIGN
%token MINUSMINUS
%token MOD
%token MODULE
%token NEQ
%token NETWORK
%token NEW
%token NONE
%token NOT_IN
%token OBJECT
%token ON
%token OPTIONAL
%token OR
%token PACK
%token PLUSASSIGN
%token PLUSPLUS
%token PORT
%token POW
%token PRINT
%token PRIORITY
%token PRIVATE
%token PUBLIC
%token REGEXP
%token RESULT
%token RETURN
%token SET
%token SHIFTLEFT
%token SHIFTRIGHT
%token SINK
%token SKIP
%token STOP
%token STREAM           "stream"
%token STRING
%token STRUCT
%token SWITCH
%token CONFIRM "confirm"
%token REJECT_ "reject"
%token THROW
%token TIME
%token TIME_NS
%token TIMER
%token TIMESASSIGN
%token TRY
%token TRYATTR
%token TUPLE
%token TYPE
%token TYPEINFO
%token UINT
%token UINT16
%token UINT32
%token UINT64
%token UINT8
%token UNIT
%token UNPACK
%token UNSET
%token VAR
%token VECTOR
%token VIEW
%token VOID
%token WHILE

%type <hilti::ID>                           local_id scoped_id dotted_id unit_hook_id
%type <hilti::Declaration*>               local_decl local_init_decl global_decl type_decl import_decl constant_decl function_decl global_scope_decl property_decl hook_decl struct_field export_decl
%type <hilti::Declarations>                 struct_fields
%type <hilti::UnqualifiedType*>           base_type_no_ref base_type type type_no_ref tuple_type struct_type enum_type unit_type bitfield_type reference_type
%type <hilti::QualifiedType*>             qtype func_result opt_func_result unit_field_base_type
%type <hilti::Ctor*>                      ctor tuple struct_ regexp list vector map set unit_field_ctor
%type <hilti::Expression*>                expr tuple_elem tuple_expr member_expr ctor_expr expr_or_error expr_1 opt_init_expression opt_unit_field_condition unit_field_repeat opt_unit_field_repeat opt_unit_switch_expr opt_bitfield_range_value expr_no_or_error call_expr
%type <hilti::Expressions>                  opt_tuple_elems1 opt_tuple_elems2 exprs opt_exprs opt_unit_field_args opt_unit_field_sinks case_exprs
%type <hilti::type::function::Parameter*> func_param
%type <hilti::parameter::Kind>              opt_func_param_kind
%type <hilti::type::function::Flavor>       opt_func_flavor
%type <hilti::type::function::CallingConvention>  opt_func_cc
%type <hilti::declaration::Linkage>         opt_linkage
%type <hilti::declaration::Parameters>      func_params opt_func_params opt_unit_params opt_unit_hook_params
%type <hilti::Statement*>                 stmt stmt_decl stmt_expr opt_else_block
%type <hilti::statement::Block*>          block braced_block
%type <hilti::Statements>                   stmts opt_stmts
%type <hilti::Attribute*>                 attribute unit_hook_attribute
%type <hilti::AttributeSet*>              opt_attributes opt_unit_hook_attributes
%type <hilti::type::tuple::Element*>      tuple_type_elem
%type <hilti::type::tuple::Elements>        tuple_type_elems
%type <hilti::ctor::struct_::Fields>        struct_elems
%type <hilti::ctor::struct_::Field*>      struct_elem
%type <hilti::ctor::map::Elements>          map_elems opt_map_elems
%type <hilti::ctor::map::Element*>        map_elem
%type <hilti::type::enum_::Label*>        enum_label
%type <hilti::type::enum_::Labels>          enum_labels
%type <hilti::type::bitfield::BitRanges>    bitfield_bit_ranges opt_bitfield_bit_ranges
%type <hilti::type::bitfield::BitRange*>  bitfield_bit_range
%type <hilti::ctor::regexp::Patterns> re_patterns
%type <hilti::ctor::regexp::Pattern>        re_pattern_constant opt_re_pattern_constant_flags
%type <hilti::statement::switch_::Case*>  switch_case
%type <hilti::statement::switch_::Cases>    switch_cases

%type <std::pair<hilti::Declarations, hilti::Statements>> global_scope_items

// Spicy-only
%type <hilti::ID>                            opt_unit_field_id
%type <spicy::declaration::Hook*>          unit_hook
%type <spicy::declaration::Hooks>            opt_unit_item_hooks unit_hooks
%type <spicy::type::unit::Item*>           unit_item unit_variable unit_field unit_field_in_container unit_wide_hook unit_property unit_switch unit_sink unit_block scoped_id_in_container
%type <spicy::type::unit::Items>             unit_items opt_unit_items opt_unit_block_else_items
%type <spicy::type::unit::item::switch_::Case*>   unit_switch_case
%type <spicy::type::unit::item::switch_::Cases>     unit_switch_cases
%type <std::pair<hilti::QualifiedType*, hilti::Expression*>> global_decl_type_and_init

%type <int64_t>  const_sint
%type <uint64_t> const_uint
%type <bool>     opt_skip opt_skip_

// NOTE: Operator precedence is documented in doc/programming/language/precedence.rst
// Update that file when any changes are made here.
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

// Magic states sent by the scanner to provide two separate entry points.
%token START_MODULE START_EXPRESSION;
%start start;

start         : START_MODULE module
              | START_EXPRESSION start_expr
              ;

start_expr    : expr                             { driver->setDestinationExpression(std::move($1)); }

module        : MODULE local_id ';'              { _docs.emplace_back(driver->docGetAndClear()); }
                global_scope_items               { auto uid = hilti::declaration::module::UID($2, hilti::rt::filesystem::path(*driver->currentFile()));
                                                   auto m = builder->declarationModule(uid, {}, std::move($5.first), std::move($5.second), __loc__);
                                                   m->setDocumentation(_docs.back());
                                                   driver->setDestinationModule(std::move(m));
                                                 }
              ;

/* IDs */

local_id      : IDENT                            { std::string name($1);

                                                   if ( ! driver->builder()->options().skip_validation ) {
                                                       if ( name.find('-') != std::string::npos)
                                                           hilti::logger().error(hilti::util::fmt("Invalid ID '%s': cannot contain '-'", name), __loc__.location());

                                                       if ( name.substr(0, 2) == "__" )
                                                           hilti::logger().error(hilti::util::fmt("Invalid ID '%s': cannot start with '__'", name), __loc__.location());

                                                       const auto prefix_local = HILTI_INTERNAL_ID("");
                                                       if ( name.starts_with(prefix_local) )
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
              | hook_decl                        { $$ = std::move($1); }
              | export_decl                      { $$ = std::move($1); }

type_decl     : opt_linkage TYPE scoped_id '='   { _docs.emplace_back(driver->docGetAndClear()); }
                qtype opt_attributes ';'         { if ( auto u = $6->type()->tryAs<type::Unit>(); u && $7 && *$7 ) {
                                                      u->setAttributes(builder->context(), $7);
                                                      $7 = {}; // don't associate with declaration
                                                   }

                                                   // Type decls can have attributes, but only for certain types
                                                   if ( $7 && ! $7->attributes().empty() ) {
                                                      auto ty = $6->type();
                                                      if ( ! (ty->isA<hilti::type::Struct>() || ty->isA<hilti::type::Enum>() || ty->isA<hilti::type::Bitfield>()) )
                                                          error(@7, "attributes are not allowed on type aliases");
                                                   }

                                                   $$ = builder->declarationType(std::move($3), std::move($6), std::move($7), std::move($1), __loc__);
                                                   $$->setDocumentation(_docs.back());
                                                   _docs.pop_back();
                                                 }

constant_decl : opt_linkage CONST scoped_id      { _docs.emplace_back(driver->docGetAndClear()); }
                '=' expr ';'                     { $$ = builder->declarationConstant($3, $6, $1, __loc__);
                                                   $$->setDocumentation(_docs.back());
                                                   _docs.pop_back();
                                                 }

              | opt_linkage CONST scoped_id      { _docs.emplace_back(driver->docGetAndClear()); }
                ':' qtype '=' expr ';'            { $$ = builder->declarationConstant($3, $6, $8, $1, __loc__);
                                                   $$->setDocumentation(_docs.back());
                                                   _docs.pop_back();
                                                 }
              ;

local_decl    : LOCAL scoped_id '=' expr ';'     { $$ = builder->declarationLocalVariable($2, $4, __loc__); }
              | LOCAL scoped_id ':' qtype ';'     { $$ = builder->declarationLocalVariable($2, $4, {}, __loc__); }
              | LOCAL scoped_id ':' qtype '=' expr ';'
                                                 { $$ = builder->declarationLocalVariable($2, $4, $6, __loc__); }
              ;

local_init_decl
              : LOCAL local_id ':' qtype '=' expr
                                                 { $$ = builder->declarationLocalVariable($2, $4, $6, __loc__); }
              | LOCAL local_id '=' expr
                                                 { $$ = builder->declarationLocalVariable($2, $4, __loc__); }
              ;

global_decl   : opt_linkage GLOBAL scoped_id     { _docs.emplace_back(driver->docGetAndClear()); }
                '=' expr ';'                     { $$ = builder->declarationGlobalVariable($3, $6, $1, __loc__);
                                                   $$->setDocumentation(_docs.back());
                                                   _docs.pop_back();
                                                 }

              | opt_linkage GLOBAL scoped_id     { _docs.emplace_back(driver->docGetAndClear()); }
                ':' global_decl_type_and_init    { $$ = builder->declarationGlobalVariable($3, $6.first, $6.second, $1, __loc__);
                                                   $$->setDocumentation(_docs.back());
                                                   _docs.pop_back();
                                                 }
              ;

global_decl_type_and_init
              : qtype ';'                         { $$ = std::make_pair($1, nullptr); }
              | qtype '=' expr ';'                { $$ = std::make_pair($1, $3); }

function_decl : opt_linkage FUNCTION opt_func_flavor opt_func_cc scoped_id '(' opt_func_params ')' opt_func_result opt_attributes
                                                 { _docs.emplace_back(driver->docGetAndClear()); }
                ';'                              {
                                                    auto ftype = builder->typeFunction($9, $7, $3, $4, __loc__);
                                                    auto func = builder->function($5, std::move(ftype), {}, $10, __loc__);
                                                    $$ = builder->declarationFunction(std::move(func), $1, __loc__);
                                                    $$->setDocumentation(_docs.back());
                                                    _docs.pop_back();
                                                 }

              | opt_linkage FUNCTION opt_func_flavor opt_func_cc scoped_id '(' opt_func_params ')' opt_func_result opt_attributes
                                                 { _docs.emplace_back(driver->docGetAndClear()); }
                braced_block                     {
                                                    auto ftype = builder->typeFunction($9, $7, $3, $4, __loc__);
                                                    auto func = builder->function($5, std::move(ftype), $12, $10, __loc__);
                                                    $$ = builder->declarationFunction(std::move(func), $1, __loc__);
                                                    $$->setDocumentation(_docs.back());
                                                    _docs.pop_back();
                                                 }
              ;

import_decl   : IMPORT local_id ';'              { $$ = builder->declarationImportedModule(std::move($2), std::string(".spicy"), __loc__); }
              | IMPORT local_id FROM dotted_id ';' { $$ = builder->declarationImportedModule(std::move($2), std::string(".spicy"), std::move($4), __loc__); }
              ;

property_decl : PROPERTY ';'                     { $$ = builder->declarationProperty(ID(std::move($1)), __loc__); }
              | PROPERTY '=' expr ';'            { $$ = builder->declarationProperty(ID(std::move($1)), std::move($3), __loc__); }
              ;

hook_decl     : ON unit_hook_id unit_hook        { ID unit = $2.namespace_();
                                                   if ( unit.empty() )
                                                      error(@$, "hook requires unit namespace");

                                                   $$ = builder->declarationUnitHook(std::move($2), std::move($3), __loc__);
                                                 }
              ;

export_decl   : EXPORT scoped_id ';'             { $$ = builder->declarationExport(std::move($2), __loc__); }
              ;

opt_linkage   : PUBLIC                           { $$ = hilti::declaration::Linkage::Public; }
              | PRIVATE                          { $$ = hilti::declaration::Linkage::Private; }
              | /* empty */                      { $$ = hilti::declaration::Linkage::Private; }

/* Function helpers */

opt_func_flavor : /* empty */                    { $$ = hilti::type::function::Flavor::Function; }

opt_func_cc   : CSTRING                          { try {
                                                       $$ = hilti::type::function::calling_convention::from_string($1);
                                                   } catch ( std::out_of_range& e ) {
                                                       error(@$, "unknown calling convention");
                                                   }
                                                 }
              | /* empty */                      { $$ = hilti::type::function::CallingConvention::Standard; }


opt_func_params
              : func_params                      { $$ = std::move($1); }
              | /* empty */                      { $$ = hilti::type::function::Parameters{}; }

func_params   : func_params ',' func_param       { $$ = std::move($1); $$.push_back($3); }
              | func_param                       { $$ = hilti::type::function::Parameters{$1}; }

func_param    : opt_func_param_kind local_id ':' type opt_init_expression opt_attributes
                                                 { $$ = builder->declarationParameter($2, $4, $1, $5, $6, __loc__); }

func_result   : ':' qtype                        { $$ = std::move($2); }

opt_func_result : func_result                    { $$ = std::move($1); }
                | /* empty */                    { $$ = builder->qualifiedType(builder->typeVoid(), hilti::Constness::Const); }

opt_func_param_kind
              : INOUT                            { $$ = hilti::parameter::Kind::InOut; }
              | /* empty */                      { $$ = hilti::parameter::Kind::In; }
              ;

opt_init_expression : '=' expr                   { $$ = std::move($2); }
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
              | /* empty */                      { $$ = hilti::Statements{}; }

stmts         : stmts stmt                       { $$ = std::move($1); $$.push_back($2); }
              | stmt                             { $$ = Statements{std::move($1)}; }

stmt          : stmt_expr ';'                    { $$ = std::move($1); }
              | stmt_decl                        { $$ = std::move($1); }
              | braced_block                     { $$ = std::move($1); }
              | ASSERT expr ';'                  { $$ = builder->statementAssert(std::move($2), {}, __loc__); }
              | ASSERT_EXCEPTION expr_no_or_error ':' expr ';'
                                                 { $$ = builder->statementAssert(hilti::statement::assert::Exception(), std::move($2), {}, std::move($4), __loc__); }
              | ASSERT_EXCEPTION expr_no_or_error ';'
                                                 { $$ = builder->statementAssert(hilti::statement::assert::Exception(), std::move($2), {}, {}, __loc__); }
              | BREAK ';'                        { $$ = builder->statementBreak(__loc__); }
              | CONTINUE ';'                     { $$ = builder->statementContinue(__loc__); }
              | FOR '(' local_id IN expr ')' block
                                                 { $$ = builder->statementFor(std::move($3), std::move($5), std::move($7), __loc__); }
              | IF '(' expr ')' block opt_else_block
                                                 { $$ = builder->statementIf(std::move($3), std::move($5), std::move($6), __loc__); }
              | IF '(' local_init_decl ')' block opt_else_block
                                                 { $$ = builder->statementIf(std::move($3), {}, std::move($5), std::move($6), __loc__); }
              | IF '(' local_init_decl ';' expr ')' block opt_else_block
                                                 { $$ = builder->statementIf(std::move($3), std::move($5), std::move($7), std::move($8), __loc__); }
              | PRINT opt_exprs ';'              { $$ = builder->statementPrint(std::move($2), __loc__); }
              | RETURN ';'                       { $$ = builder->statementReturn(__loc__); }
              | RETURN expr ';'                  { $$ = builder->statementReturn(std::move($2), __loc__); }
              | STOP ';'                         { $$ = builder->statementStop(__loc__); }
              | THROW expr ';'                   { $$ = builder->statementThrow(builder->exception(builder->typeName("~spicy_rt::ParseError"), $2, __loc__), __loc__); }
              | SWITCH '(' expr ')' '{' switch_cases '}'
                                                 { $$ = builder->statementSwitch(std::move($3), std::move($6), __loc__); }
              | SWITCH '(' local_init_decl ')' '{' switch_cases '}'
                                                 { $$ = builder->statementSwitch(std::move($3), std::move($6), __loc__); }
              | CONFIRM ';'                      { $$ = builder->statementConfirm(__loc__); }
              | REJECT_ ';'                      { $$ = builder->statementReject(__loc__); }
              | WHILE '(' local_init_decl ';' expr ')' block
                                                 { $$ = builder->statementWhile(std::move($3), std::move($5), std::move($7), nullptr, __loc__); }
              | WHILE '(' expr ')' block
                                                 { $$ = builder->statementWhile(std::move($3), std::move($5), nullptr, __loc__); }
              | WHILE '(' local_init_decl ')' block
                                                 { $$ = builder->statementWhile(std::move($3), {}, std::move($5), nullptr, __loc__); }

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

switch_cases  : switch_cases switch_case         { $$ = std::move($1); $$.push_back(std::move($2)); }
              | switch_case                      { $$ = hilti::statement::switch_::Cases({ std::move($1) }); }

switch_case   : CASE case_exprs ':' block             { $$ = builder->statementSwitchCase(std::move($2), std::move($4), __loc__); }
              | DEFAULT ':' block                { $$ = builder->statementSwitchCase(hilti::statement::switch_::Default(), std::move($3), __loc__); }

case_exprs    : case_exprs ',' expr_no_or_error  { $$ = std::move($1); $$.push_back(std::move($3)); }
              | expr_no_or_error                 { $$ = hilti::Expressions{std::move($1)}; }

stmt_decl     : local_decl                       { $$ = builder->statementDeclaration($1, __loc__); }
              | type_decl                        { $$ = builder->statementDeclaration($1, __loc__); }
              | constant_decl                    { $$ = builder->statementDeclaration($1, __loc__); }
              ;

stmt_expr     : expr                             { $$ = builder->statementExpression($1, __loc__); }

/* Types */

base_type_no_ref
              : ANY                              { $$ = builder->typeAny(__loc__); }
              | ADDRESS                          { $$ = builder->typeAddress(__loc__); }
              | BOOL                             { $$ = builder->typeBool(__loc__); }
              | BYTES                            { $$ = builder->typeBytes(__loc__); }
              | __ERROR                          { $$ = builder->typeError(__loc__); }
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

              | INT8                             { $$ = builder->typeSignedInteger(8, __loc__); }
              | INT16                            { $$ = builder->typeSignedInteger(16, __loc__); }
              | INT32                            { $$ = builder->typeSignedInteger(32, __loc__); }
              | INT64                            { $$ = builder->typeSignedInteger(64, __loc__); }
              | UINT8                            { $$ = builder->typeUnsignedInteger(8, __loc__); }
              | UINT16                           { $$ = builder->typeUnsignedInteger(16, __loc__); }
              | UINT32                           { $$ = builder->typeUnsignedInteger(32, __loc__); }
              | UINT64                           { $$ = builder->typeUnsignedInteger(64, __loc__); }

              | CONST_ITERATOR type_param_begin qtype type_param_end      { $$ = iteratorForType(builder, std::move($3), __loc__)->type(); }
              | ITERATOR type_param_begin qtype type_param_end            { $$ = iteratorForType(builder, std::move($3), __loc__)->type(); }
              | OPTIONAL type_param_begin qtype type_param_end            { $$ = builder->typeOptional($3, __loc__); }
              | RESULT type_param_begin qtype type_param_end              { $$ = builder->typeResult($3, __loc__); }
              | VIEW type_param_begin qtype type_param_end                { $$ = viewForType(builder, std::move($3), __loc__)->type(); }

              | MAP type_param_begin qtype ',' qtype type_param_end        { $$ = builder->typeMap(std::move($3), std::move($5), __loc__); }
              | SET type_param_begin qtype type_param_end                 { $$ = builder->typeSet(std::move($3), __loc__); }
              | VECTOR type_param_begin qtype type_param_end              { $$ = builder->typeVector(std::move($3), __loc__); }

              | SINK                             { $$ = builder->typeSink(__loc__); }

              | LIBRARY_TYPE '(' CSTRING ')'     { $$ = builder->typeLibrary(std::move($3), __loc__); }
              | LIBRARY_TYPE_CONST '(' CSTRING ')'
                                                 { $$ = builder->typeLibrary(hilti::Constness::Const, std::move($3), __loc__); }

              | tuple_type                       { $$ = std::move($1); }
              | struct_type                      { $$ = std::move($1); }
              | enum_type                        { $$ = std::move($1); }
              | bitfield_type                    { $$ = std::move($1); }
              | unit_type                        { $$ = std::move($1); }

              ;

/* We split this out from "base_type" because it can lead to ambigitious in some contexts. */
reference_type: qtype '&'                        { $1->setSide(hilti::Side::LHS);
                                                   $1->setConst(hilti::Constness::Mutable);
                                                   $$ = builder->typeStrongReference(std::move($1), __loc__);
                                                 }

base_type     : base_type_no_ref                 { $$ = std::move($1); }
                reference_type: qtype '&'        { $1->setSide(hilti::Side::LHS);
                                                   $1->setConst(hilti::Constness::Mutable);
                                                   $$ = builder->typeStrongReference(std::move($1), __loc__);
                                                 }
              ;

type          : base_type                        { $$ = std::move($1); }
              | reference_type                   { $$ = std::move($1); }
              | scoped_id                        { $$ = builder->typeName(std::move($1)); }
              ;

type_no_ref   : base_type                        { $$ = std::move($1); }
              | scoped_id                        { $$ = builder->typeName(std::move($1)); }
              ;

qtype         : type_no_ref                      { $$ = builder->qualifiedType(std::move($1), hilti::Constness::Mutable, __loc__); }
              | CONST type_no_ref                { $$ = builder->qualifiedType(std::move($2), hilti::Constness::Const, __loc__); }
              | reference_type                   { $$ = builder->qualifiedType(std::move($1), hilti::Constness::Const, __loc__); }
              | AUTO                             { $$ = builder->qualifiedType(builder->typeAuto(__loc__), hilti::Constness::Const, __loc__); }
              ;

type_param_begin:
              '<'
              { driver->disableExpressionMode(); }

type_param_end:
              '>'
              { driver->enableExpressionMode(); }

tuple_type    : TUPLE type_param_begin '*' type_param_end                { $$ = builder->typeTuple(hilti::type::Wildcard(), __loc__); }
              | TUPLE type_param_begin tuple_type_elems type_param_end   { $$ = builder->typeTuple(std::move($3), __loc__); }
              ;

tuple_type_elems
              : tuple_type_elems ',' tuple_type_elem
                                                 { $$ = std::move($1); $$.push_back(std::move($3)); }
              | tuple_type_elems ','             { $$ = std::move($1); }
              | tuple_type_elem                  { $$ = hilti::type::tuple::Elements{std::move($1)}; }
              ;

tuple_type_elem
              : qtype                             { $$ = builder->typeTupleElement(std::move($1)); }
              | local_id ':' qtype                { $$ = builder->typeTupleElement(std::move($1), std::move($3)); }
              ;

struct_type   : STRUCT '{' struct_fields '}'     { $$ = builder->typeStruct(std::move($3), __loc__); }

struct_fields : struct_fields struct_field       { $$ = std::move($1); $$.push_back($2); }
              | /* empty */                      { $$ = Declarations{}; }

struct_field  : local_id ':' qtype opt_attributes ';' { $$ = builder->declarationField(std::move($1), std::move($3), std::move($4), __loc__); }

enum_type     : ENUM '{' enum_labels '}'         { $$ = builder->typeEnum(std::move($3), __loc__); }

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
              | /* empty */                      { $$ = hilti::type::bitfield::BitRanges(); }

bitfield_bit_ranges
              : bitfield_bit_ranges bitfield_bit_range
                                                 { $$ = std::move($1); $$.push_back(std::move($2));  }
              | bitfield_bit_range               { $$ = hilti::type::bitfield::BitRanges(); $$.push_back(std::move($1)); }

bitfield_bit_range
              : local_id ':' CUINTEGER DOTDOT CUINTEGER opt_bitfield_range_value opt_attributes ';'
                                                 { $$ = builder->typeBitfieldBitRange(std::move($1), $3, $5, _field_width, std::move($7), std::move($6), __loc__); }
              | local_id ':' CUINTEGER opt_bitfield_range_value opt_attributes ';'
                                                 { $$ = builder->typeBitfieldBitRange(std::move($1), $3, $3, _field_width, std::move($5), std::move($4), __loc__); }

opt_bitfield_range_value
              : '=' expr                         { $$ = std::move($2); }
              | /* empty */                      { $$ = {}; }
              ;


/* --- Begin of Spicy units --- */

unit_type     : UNIT opt_unit_params '{' opt_unit_items '}'
                                                 { $$ = builder->typeUnit(std::move($2), std::move($4), {}, __loc__); }

opt_unit_params
              : '(' opt_func_params ')'          { $$ = std::move($2); }
              | /* empty */                      { $$ = hilti::type::function::Parameters{}; }

unit_items    : unit_items unit_item             { $$ = std::move($1); $$.push_back(std::move($2)); }
              | unit_item                        { $$ = spicy::type::unit::Items(); $$.push_back($1); }

opt_unit_items: unit_items                       { $$ = std::move($1);}
              | /* empty */                      { $$ = spicy::type::unit::Items{}; }


unit_item     : unit_field                       { $$ = std::move($1); }
              | unit_variable                    { $$ = std::move($1); }
              | unit_wide_hook                   { $$ = std::move($1); }
              | unit_property                    { $$ = std::move($1); }
              | unit_sink                        { $$ = std::move($1); }
              | unit_switch                      { $$ = std::move($1); }
              | unit_block                       { $$ = std::move($1); }
              ;


unit_variable : VAR local_id ':' qtype opt_init_expression opt_attributes ';'
                                                 { $$ = builder->typeUnitItemVariable(std::move($2), std::move($4), std::move($5), std::move($6), __loc__); }

unit_sink     : SINK local_id opt_attributes ';' { $$ = builder->typeUnitItemSink(std::move($2), std::move($3), __loc__); }

unit_property : PROPERTY opt_attributes ';'      { $$ = builder->typeUnitItemProperty(ID(std::move($1)), std::move($2), false, __loc__); };
              | PROPERTY '=' expr opt_attributes';'
                                                 { $$ = builder->typeUnitItemProperty(ID(std::move($1)), std::move($3), std::move($4), false, __loc__); };
              | PROPERTY '=' base_type_no_ref ';'       { $$ = builder->typeUnitItemProperty(ID(std::move($1)), builder->expressionType(builder->qualifiedType(std::move($3), hilti::Constness::Mutable)), {}, false, __loc__); };

unit_field_base_type : base_type                   {   if ( $1->isA<hilti::type::Vector>() )
                                                         error(@$, "vector<T> syntax is no longer supported for parsing sequences; use T[] instead.");
                                                     $$ = builder->qualifiedType(std::move($1), hilti::Constness::Mutable);
                                                 }

unit_field    : opt_unit_field_id ':' opt_skip unit_field_base_type opt_attributes opt_unit_field_condition opt_unit_field_sinks opt_unit_item_hooks
                                                 { $$ = builder->typeUnitItemUnresolvedField(std::move($1), std::move($4), $3, {}, std::move($7), std::move($5), std::move($6), std::move($8), __loc__); }
              | opt_unit_field_id ':' opt_skip unit_field_base_type unit_field_repeat opt_attributes opt_unit_field_condition opt_unit_field_sinks opt_unit_item_hooks
                                                 {   auto typeField = builder->typeUnitItemUnresolvedField({}, std::move($4), false, {}, {}, {}, {}, {}, toMeta(@4));
                                                     $$ = builder->typeUnitItemUnresolvedField(std::move($1), std::move(typeField), $3, {}, std::move($5), std::move($8), std::move($6), std::move($7), std::move($9), __loc__);
                                                 }

              | opt_unit_field_id ':' opt_skip unit_field_ctor opt_unit_field_repeat opt_attributes opt_unit_field_condition opt_unit_field_sinks opt_unit_item_hooks
                                                 { $$ = builder->typeUnitItemUnresolvedField(std::move($1), std::move($4), $3, {}, std::move($5), std::move($8), std::move($6), std::move($7), std::move($9), __loc__); }

              | opt_unit_field_id ':' opt_skip scoped_id opt_unit_field_args opt_attributes opt_unit_field_condition opt_unit_field_sinks opt_unit_item_hooks
                                                 { $$ = builder->typeUnitItemUnresolvedField(std::move($1), std::move($4), $3, std::move($5), std::move($8), std::move($6), std::move($7), std::move($9), __loc__); }
              | opt_unit_field_id ':' opt_skip scoped_id_in_container unit_field_repeat opt_attributes opt_unit_field_condition opt_unit_field_sinks opt_unit_item_hooks
                                                 { $$ = builder->typeUnitItemUnresolvedField(std::move($1), $4, $3, {}, std::move($5), std::move($8), std::move($6), std::move($7), std::move($9), __loc__); }
              | opt_unit_field_id ':' opt_skip '(' unit_field_in_container ')' opt_unit_field_repeat opt_attributes opt_unit_field_condition opt_unit_field_sinks opt_unit_item_hooks
                                                 { $$ = builder->typeUnitItemUnresolvedField(std::move($1), std::move($5), $3, {}, std::move($7), std::move($10), std::move($8), std::move($9), std::move($11), __loc__); }

const_sint    : CUINTEGER                        { $$ = check_int64_range($1, true, __loc__); }
              | '+' CUINTEGER                    { $$ = check_int64_range($2, true, __loc__); }
              | '-' CUINTEGER                    { $$ = -check_int64_range($2, false, __loc__); }

const_uint    : CUINTEGER                        { $$ = $1; }
              | '+' CUINTEGER                    { $$ = $2; }

unit_field_ctor
              : ctor                             { $$ = std::move($1); }
              | UINT8 '(' const_uint ')'         { $$ = builder->ctorUnsignedInteger($3, 8, __loc__); }
              | UINT16 '(' const_uint ')'        { $$ = builder->ctorUnsignedInteger($3, 16, __loc__); }
              | UINT32 '(' const_uint ')'        { $$ = builder->ctorUnsignedInteger($3, 32, __loc__); }
              | UINT64 '(' const_uint ')'        { $$ = builder->ctorUnsignedInteger($3, 64, __loc__); }
              | INT8 '(' const_sint ')'          { $$ = builder->ctorSignedInteger($3, 8, __loc__); }
              | INT16 '(' const_sint ')'         { $$ = builder->ctorSignedInteger($3, 16, __loc__); }
              | INT32 '(' const_sint ')'         { $$ = builder->ctorSignedInteger($3, 32, __loc__); }
              | INT64 '(' const_sint ')'         { $$ = builder->ctorSignedInteger($3, 64, __loc__); }

unit_field_in_container
              : unit_field_ctor opt_unit_field_args opt_attributes
                                                 { $$ = builder->typeUnitItemUnresolvedField({}, std::move($1), false, std::move($2), {}, {}, std::move($3), {}, {}, __loc__); }
              | scoped_id opt_unit_field_args opt_attributes
                                                 { $$ = builder->typeUnitItemUnresolvedField({}, std::move($1), false, std::move($2), {}, std::move($3), {}, {}, __loc__); }
              | scoped_id_in_container unit_field_repeat opt_attributes
                                                 { $$ = builder->typeUnitItemUnresolvedField({}, $1, false, {}, std::move($2), {}, std::move($3), {}, {}, __loc__); }
              | unit_field_base_type opt_unit_field_args opt_attributes
                                                 { $$ = builder->typeUnitItemUnresolvedField({}, $1, false, std::move($2), {}, std::move($3), {}, {}, __loc__); }
              | unit_field_base_type unit_field_repeat opt_unit_field_args opt_attributes
                                                 {   auto typeField = builder->typeUnitItemUnresolvedField({}, std::move($1), false, {}, {}, {}, {}, {}, toMeta(@1));
                                                     $$ = builder->typeUnitItemUnresolvedField({}, std::move(typeField), false, {}, std::move($2), {}, std::move($4), {}, {}, __loc__);
                                                 }

scoped_id_in_container
              : scoped_id opt_unit_field_args    { $$ = builder->typeUnitItemUnresolvedField({}, std::move($1), false, std::move($2), {}, {}, {}, {}, __loc__); }

unit_wide_hook : ON unit_hook_id unit_hook       { $$ = builder->typeUnitItemUnitHook(std::move($2), std::move($3), __loc__); }

opt_unit_field_id
              : local_id                         { $$ = std::move($1); }
              | /* empty */                      { $$ = {}; }

opt_skip      :
              { driver->enableNewKeywordMode(); }
              opt_skip_
              { driver->disableNewKeywordMode(); $$ = $2; }

opt_skip_     :
                SKIP                             { $$ = true; }
              | /* empty */                      { $$ = false; }

opt_unit_field_args
              : '(' opt_exprs ')'                { $$ = std::move($2); }
              | /* empty */                      { $$ = hilti::Expressions(); }

unit_field_repeat
              : '[' expr ']'                     { $$ = std::move($2); }
              | '[' ']'                          { $$ = builder->null(); }

opt_unit_field_repeat
              : unit_field_repeat                { $$ = std::move($1); }
              | /* empty */                      { $$ = {}; }

opt_unit_field_condition
              : IF '(' expr ')'                  { $$ = std::move($3); }
              | /* empty */                      { $$ = {}; }

opt_unit_field_sinks
              : ARROW exprs                      { $$ = std::move($2); }
              | /* empty */                      { $$ = hilti::Expressions(); }

opt_unit_item_hooks
              : unit_hooks                       { $$ = std::move($1); }
              | ';'                              { $$ = spicy::declaration::Hooks(); }

unit_hooks    : unit_hooks unit_hook             { $$ = std::move($1); $$.push_back(std::move($2)); }
              | unit_hook                        { $$ = spicy::declaration::Hooks{std::move($1)}; }

unit_hook     : opt_unit_hook_params opt_unit_hook_attributes braced_block
                                                 { $$ = builder->declarationHook(std::move($1), std::move($3), std::move($2), __loc__); }

opt_unit_hook_params
              : '(' opt_func_params ')'          { $$ = std::move($2); }
              | /* empty */                      { $$ = hilti::type::function::Parameters{}; }

opt_unit_hook_attributes
              : opt_unit_hook_attributes unit_hook_attribute
                                                 { $1->add(builder->context(), $2); $$ = std::move($1); }
              | /* empty */                      { $$ = builder->attributeSet({}, __loc__); }

unit_hook_id: { driver->enableHookIDMode(); }
              HOOK_IDENT
              { driver->disableHookIDMode(); } { $$ = hilti::ID(hilti::util::replace($2, "%", "0x25_")); }

unit_hook_attribute
              : FOREACH                          { $$ = builder->attribute(attribute::kind::Foreach, __loc__); }
              | PRIORITY '=' expr                { $$ = builder->attribute(attribute::kind::Priority, std::move($3), __loc__); }
              | PROPERTY                         { try {
                                                       $$ = builder->attribute(hilti::attribute::kind::from_string($1), __loc__);
                                                   } catch ( std::out_of_range& e ) {
                                                       error(@$, hilti::util::fmt("unknown attribute '%s'", $1));
                                                   }
                                                 }
              | ATTRIBUTE                        { try {
                                                       $$ = builder->attribute(hilti::attribute::kind::from_string($1), __loc__);
                                                   } catch ( std::out_of_range& e ) {
                                                       error(@$, hilti::util::fmt("unknown attribute '%s'", $1));
                                                   }
                                                 }

unit_switch   : SWITCH opt_unit_switch_expr '{' unit_switch_cases '}' opt_attributes opt_unit_field_condition ';'
                                                 { $$ = builder->typeUnitItemSwitch(std::move($2), std::move($4), std::move($7), {}, std::move($6), __loc__); }

opt_unit_switch_expr: '(' expr ')'               { $$ = std::move($2); }
              | /* empty */                      { $$ = {}; }

unit_switch_cases
              : unit_switch_cases unit_switch_case
                                                 { $$ = std::move($1); $$.push_back(std::move($2)); }
              | unit_switch_case                 { $$ = spicy::type::unit::item::switch_::Cases(); $$.push_back(std::move($1)); }

unit_switch_case
              : exprs ARROW '{' unit_items '}'   { $$ = builder->typeUnitItemSwitchCase($1, $4, __loc__); }
              | '*'   ARROW '{' unit_items '}'   { $$ = builder->typeUnitItemSwitchCase($4, false, __loc__); }
              |       ARROW '{' unit_items '}'   { $$ = builder->typeUnitItemSwitchCase($3, true, __loc__); }
              | exprs ARROW unit_item            { $$ = builder->typeUnitItemSwitchCase($1, {$3}, __loc__); }
              | '*'   ARROW unit_item            { $$ = builder->typeUnitItemSwitchCase(type::unit::Items{$3}, false, __loc__); }
              |       ARROW unit_item            { $$ = builder->typeUnitItemSwitchCase(type::unit::Items{$2}, true, __loc__); }

opt_unit_block_else_items
              : ELSE '{' opt_unit_items '}'      { $$ = std::move($3); }
              | /* empty */                      { $$ = {}; }

unit_block    : IF '(' expr ')' '{' opt_unit_items '}' opt_unit_block_else_items ';'
                                                 { $$ = builder->typeUnitItemBlock(std::move($3), std::move($6), std::move($8), {}, __loc__); }

/* --- End of Spicy units --- */

/* Expressions */

expr          :
              { driver->enableExpressionMode(); }
              expr_or_error
              { driver->disableExpressionMode(); }
                                                 { $$ = std::move($2); }
              ;

expr_no_or_error
              : expr_1                           { $$ = std::move($1); }

opt_exprs     : exprs                            { $$ = std::move($1); }
              | /* empty */                      { $$ = Expressions(); }

exprs         : exprs ',' expr                   { $$ = std::move($1); $$.push_back(std::move($3)); }
              | expr                             { $$ = Expressions{std::move($1)}; }

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
              | PACK tuple_expr                  { $$ = builder->expressionUnresolvedOperator(hilti::operator_::Kind::Pack, {std::move($2)}, __loc__); }
              | UNPACK type_param_begin qtype type_param_end tuple_expr   { $$ = builder->expressionUnresolvedOperator(hilti::operator_::Kind::Unpack, {builder->expressionType(std::move($3)), std::move($5), builder->expressionCtor(builder->ctorBool(true), __loc__)}, __loc__); }
              | BEGIN_ '(' expr ')'              { $$ = builder->expressionUnresolvedOperator(hilti::operator_::Kind::Begin, {std::move($3)}, __loc__); }
              | END_ '(' expr ')'                { $$ = builder->expressionUnresolvedOperator(hilti::operator_::Kind::End, {std::move($3)}, __loc__); }
              | NEW base_type_no_ref             { $$ = builder->expressionUnresolvedOperator(hilti::operator_::Kind::New, {builder->expressionCtor(builder->ctorDefault(std::move($2))), builder->expressionCtor(builder->ctorTuple({}, __loc__))}, __loc__); }
              | NEW ctor                         { $$ = builder->expressionUnresolvedOperator(hilti::operator_::Kind::New, {builder->expressionCtor(std::move($2), __loc__),             builder->expressionCtor(builder->ctorTuple({}, __loc__))}, __loc__); }
              | NEW scoped_id                    { $$ = builder->expressionUnresolvedOperator(hilti::operator_::Kind::New, {builder->expressionName(std::move($2), __loc__), builder->expressionCtor(builder->ctorTuple({}, __loc__))}, __loc__); }
              | NEW scoped_id '(' opt_exprs ')'  { $$ = builder->expressionUnresolvedOperator(hilti::operator_::Kind::New, {builder->expressionName(std::move($2), __loc__), builder->expressionCtor(builder->ctorTuple(std::move($4), __loc__))}, __loc__); }
              | TYPEINFO '(' expr ')'            { $$ = builder->expressionTypeInfo(std::move($3), __loc__); }
              | TYPEINFO '(' base_type ')'       { $$ = builder->expressionTypeInfo(builder->expressionType(builder->qualifiedType(std::move($3), hilti::Constness::Mutable)), __loc__); }
              | ctor                             { $$ = builder->expressionCtor(std::move($1), __loc__); }
              | ctor_expr                        { $$ = std::move($1); }
              | '[' expr FOR local_id IN expr ']'{ $$ = builder->expressionListComprehension(std::move($6), std::move($2), std::move($4), {},  __loc__); }
              | '[' expr FOR local_id IN expr IF expr ']'   { $$ = builder->expressionListComprehension(std::move($6), std::move($2), std::move($4), std::move($8),  __loc__); }
              | '(' expr ')'                     { $$ = builder->expressionGrouping(std::move($2)); }
              | scoped_id                        { $$ = builder->expressionName(std::move($1), __loc__); }
              | DOLLARDOLLAR                     { $$ = builder->expressionName(std::move(HILTI_INTERNAL_ID("dd")), __loc__);}
              | DOLLAR_NUMBER                    { // $N -> $@[N] (with $@ being available internally only, not exposed to users)
                                                   auto captures = builder->expressionKeyword(hilti::expression::keyword::Kind::Captures, builder->qualifiedType(builder->typeName("~hilti::Captures"), hilti::Constness::Mutable), __loc__);
                                                   auto index = builder->expressionCtor(builder->ctorUnsignedInteger($1, 64, __loc__), __loc__);
                                                   $$ = builder->expressionUnresolvedOperator(hilti::operator_::Kind::Index, {std::move(captures), std::move(index)}, __loc__);
                                                 }
    ;

call_expr     : expr_1 '(' opt_exprs ')'         { $$ = builder->expressionUnresolvedOperator(hilti::operator_::Kind::Call, {std::move($1), builder->expressionCtor(builder->ctorTuple(std::move($3), __loc__))}, __loc__); }
              ;


member_expr   : local_id                         { $$ = builder->expressionMember(std::move($1), __loc__); }
              | STREAM                           { $$ = builder->expressionMember(ID("stream"), __loc__); } // allow methods of that name even though reserved keyword

/* Constants */

ctor          : CADDRESS                         { $$ = builder->ctorAddress(hilti::rt::Address($1), __loc__); }
              | CADDRESS '/' CUINTEGER           { $$ = builder->ctorNetwork(hilti::rt::Network($1, $3), __loc__); }
              | CBOOL                            { $$ = builder->ctorBool($1, __loc__); }
              | CBYTES                           { $$ = builder->ctorBytes(std::move($1), __loc__); }
              | CERROR                           { $$ = builder->ctorError(std::move($1), __loc__); }
              | CPORT                            { $$ = builder->ctorPort(hilti::rt::Port($1), __loc__); }
              | CNULL                            { $$ = builder->ctorNull(__loc__); }
              | CSTRING                          { $$ = builder->ctorString($1, false, __loc__); }
              | CUINTEGER                        { $$ = builder->ctorUnsignedInteger($1, 64, __loc__); }
              | '+' CUINTEGER                    { if ( $2 > static_cast<uint64_t>(std::numeric_limits<int64_t>::max()) )
                                                    hilti::logger().error("integer constant out of range", __loc__.location());

                                                   $$ = builder->ctorSignedInteger($2, 64, __loc__);
                                                 }
              | CUREAL                           { $$ = builder->ctorReal($1, __loc__); }
              | '+' CUREAL                       { $$ = builder->ctorReal($2, __loc__);; }

              /* There are more here that we could move into ctor_expr and have them use namedCtor.
                 But not sure if that'd change much so leaving here for now.
              */
              | OPTIONAL '(' expr ')'            { $$ = builder->ctorOptional(std::move($3), __loc__); }
              | RESULT '(' expr ')'              { $$ = builder->ctorResult(std::move($3), __loc__); }

              | list                             { $$ = std::move($1); }
              | map                              { $$ = std::move($1); }
              | regexp                           { $$ = std::move($1); }
              | set                              { $$ = std::move($1); }
              | struct_                          { $$ = std::move($1); }
              | tuple                            { $$ = std::move($1); }
              | vector                           { $$ = std::move($1); }
              ;

ctor_expr     : INTERVAL '(' expr ')'            { $$ = builder->namedCtor("interval", { std::move($3) }, __loc__); }
              | INTERVAL_NS '(' expr ')'         { $$ = builder->namedCtor("interval_ns", { std::move($3) }, __loc__); }
              | TIME '(' expr ')'                { $$ = builder->namedCtor("time", { std::move($3) }, __loc__); }
              | TIME_NS '(' expr ')'             { $$ = builder->namedCtor("time_ns", { std::move($3) }, __loc__); }
              | STREAM '(' expr ')'              { $$ = builder->namedCtor("stream", { std::move($3) }, __loc__); }
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
              | TUPLE '(' opt_exprs ')'          { $$ = builder->ctorTuple(std::move($3), __loc__); }

opt_tuple_elems1
              : tuple_elem                       { $$ = hilti::Expressions{std::move($1)}; }
              | tuple_elem ',' opt_tuple_elems2  { $$ = hilti::Expressions{std::move($1)}; $$.insert($$.end(), $3.begin(), $3.end()); }
              | /* empty */                      { $$ = hilti::Expressions(); }

opt_tuple_elems2
              : tuple_elem                       { $$ = hilti::Expressions{std::move($1)}; }
              | tuple_elem ',' opt_tuple_elems2  { $$ = hilti::Expressions{std::move($1)}; $$.insert($$.end(), $3.begin(), $3.end()); }
              | tuple_elem                       { $$ = hilti::Expressions{std::move($1)}; }
              | /* empty */                      { $$ = hilti::Expressions(); }


tuple_elem    : expr                             { $$ = std::move($1); }
              | NONE                             { $$ = builder->expressionCtor(builder->ctorNull(__loc__), __loc__); }

tuple_expr    : tuple                            { $$ = builder->expressionCtor(std::move($1), __loc__); }

list          : '[' opt_exprs ']'                { $$ = builder->ctorList(std::move($2), __loc__); }
              | LIST '(' opt_exprs ')'           { $$ = builder->ctorList(std::move($3), __loc__); }
              | LIST type_param_begin qtype type_param_end '(' opt_tuple_elems1 ')'
                                                 { $$ = builder->ctorList(std::move($3), std::move($6), __loc__); }

vector        : VECTOR '(' opt_exprs ')'         { $$ = builder->ctorVector(std::move($3), __loc__); }
              | VECTOR type_param_begin qtype type_param_end '(' opt_tuple_elems1 ')'
                                                 { $$ = builder->ctorVector(std::move($3), std::move($6), __loc__); }

set           : SET '(' opt_exprs ')'            { $$ = builder->ctorSet(std::move($3), __loc__); }
              | SET type_param_begin qtype type_param_end '(' opt_tuple_elems1 ')'
                                                 { $$ = builder->ctorSet(std::move($3), std::move($6), __loc__); }

map           : MAP '(' opt_map_elems ')'        { $$ = builder->ctorMap(std::move($3), __loc__); }
              | MAP type_param_begin qtype ',' qtype type_param_end '(' opt_map_elems ')'
                                                 { $$ = builder->ctorMap(std::move($3), std::move($5), std::move($8), __loc__); }

struct_       : '[' struct_elems ']'             { $$ = builder->ctorStruct(std::move($2), __loc__); }
              /* We don't allow empty structs, we parse that as empty vectors instead. */

struct_elems  : struct_elems ',' struct_elem     { $$ = std::move($1); $$.push_back($3); }
              | struct_elem                      { $$ = hilti::ctor::struct_::Fields{ std::move($1) }; }

struct_elem   : DOLLAR_IDENT '=' expr            { $$ = builder->ctorStructField(hilti::ID(std::move($1)), std::move($3)); }

regexp        : re_patterns                      { $$ = builder->ctorRegExp(std::move($1), {}, __loc__); }

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

map_elem      : expr_no_or_error ':' expr        { $$ = builder->ctorMapElement($1, $3); }

/* Attributes */

attribute     : ATTRIBUTE                       { try {
                                                       $$ = builder->attribute(hilti::attribute::kind::from_string($1), __loc__);
                                                   } catch ( std::out_of_range& e ) {
                                                       error(@$, hilti::util::fmt("unknown attribute '%s'", $1));
                                                       $$ = nullptr;
                                                   }
                                                }
              | ATTRIBUTE '=' expr              { try {
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

void spicy::detail::parser::Parser::error(const Parser::location_type& l, const std::string& m) {
    driver->error(m, toMeta(l));
}
