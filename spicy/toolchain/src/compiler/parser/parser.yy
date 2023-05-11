/* Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details. */

/* This grammar is written against the bison-3.3 API. If an older Bison version
 * was detected we perform preprocessing to support versions down to at least
 * bison-3.0, see the CMake macro `BISON_TARGET_PP`. */
%require "3.3"

%skeleton "lalr1.cc"                          /*  -*- C++ -*- */
%defines

%{
namespace spicy { namespace detail { class Parser; } }

#include <spicy/compiler/detail/parser/driver.h>

%}

%locations
%initial-action
{
    @$.begin.filename = @$.end.filename = driver->currentFile();
    @$.begin.line = @$.end.line = driver->currentLine();
};

%parse-param {class Driver* driver}
%lex-param   {class Driver* driver}

%define api.namespace {spicy::detail::parser}
%define api.parser.class {Parser}
%define parse.error verbose
%define api.value.type variant

%debug
%verbose

%glr-parser
%expect 125
%expect-rr 164

%{

#include <spicy/compiler/detail/parser/scanner.h>

#undef yylex
#define yylex driver->scanner()->lex

static hilti::Meta toMeta(spicy::detail::parser::location l) {
    return hilti::Meta(hilti::Location(*l.begin.filename, l.begin.line, l.end.line, l.begin.column, l.end.column));
}

static hilti::Type iteratorForType(hilti::Type t, bool const_, hilti::Meta m) {
    if ( hilti::type::isIterable(t) )
        return t.iteratorType(const_);
    else {
        hilti::logger().error(hilti::util::fmt("type '%s' is not iterable", t), m.location());
        return hilti::type::Error(m);
        }
}

static hilti::Type viewForType(hilti::Type t, hilti::Meta m) {
    if ( hilti::type::isViewable(t) )
        return t.viewType();
    else {
        hilti::logger().error(hilti::util::fmt("type '%s' is not viewable", t), m.location());
        return hilti::type::Error(m);
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
%token LIBRARY_TYPE     "library type"
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
%token NET
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

%type <hilti::ID>                                    local_id scoped_id dotted_id unit_hook_id
%type <hilti::Declaration>                           local_decl local_init_decl global_decl type_decl import_decl constant_decl function_decl global_scope_decl property_decl hook_decl struct_field
%type <std::vector<hilti::Declaration>>              struct_fields
%type <hilti::Type>                                  base_type_no_ref base_type type tuple_type struct_type enum_type unit_type bitfield_type reference_type
%type <hilti::Ctor>                                  ctor tuple struct_ regexp list vector map set unit_field_ctor
%type <hilti::Expression>                            expr tuple_elem tuple_expr member_expr ctor_expr expr_0 expr_1 expr_2 expr_3 expr_4 expr_5 expr_6 expr_7 expr_8 expr_9 expr_a expr_b expr_c expr_d expr_e expr_f expr_g
%type <std::vector<hilti::Expression>>               opt_tuple_elems1 opt_tuple_elems2 exprs opt_exprs opt_unit_field_args opt_unit_field_sinks
%type <std::optional<hilti::Statement>>              opt_else_block
%type <std::optional<hilti::Expression>>             opt_init_expression opt_unit_field_condition unit_field_repeat opt_unit_field_repeat opt_unit_switch_expr
%type <hilti::type::function::Parameter>             func_param
%type <hilti::declaration::parameter::Kind>          opt_func_param_kind
%type <hilti::type::function::Result>                func_result opt_func_result
%type <hilti::type::function::Flavor>                opt_func_flavor
%type <hilti::function::CallingConvention>           opt_func_cc
%type <hilti::declaration::Linkage>                  opt_linkage
%type <std::vector<hilti::type::function::Parameter>>func_params opt_func_params opt_unit_params opt_unit_hook_params
%type <hilti::Statement>                             stmt stmt_decl stmt_expr block braced_block
%type <std::vector<hilti::Statement>>                stmts opt_stmts
%type <hilti::Attribute>                             attribute unit_hook_attribute
%type <std::optional<hilti::AttributeSet>>           opt_attributes opt_unit_hook_attributes
%type <hilti::type::tuple::Element>                  tuple_type_elem
%type <std::vector<hilti::type::tuple::Element>>     tuple_type_elems
%type <std::vector<hilti::ctor::struct_::Field>>     struct_elems
%type <hilti::ctor::struct_::Field>                   struct_elem
%type <std::vector<hilti::ctor::map::Element>>        map_elems opt_map_elems
%type <hilti::ctor::map::Element>                     map_elem
%type <hilti::type::enum_::Label>                     enum_label
%type <std::vector<hilti::type::enum_::Label>>        enum_labels
%type <std::vector<spicy::type::bitfield::Bits>>      bitfield_bits opt_bitfield_bits
%type <spicy::type::bitfield::Bits>                   bitfield_bits_spec
%type <std::vector<std::string>>                      re_patterns
%type <std::string>                                   re_pattern_constant
%type <hilti::statement::switch_::Case>               switch_case
%type <std::vector<hilti::statement::switch_::Case>>  switch_cases

%type <std::pair<std::vector<hilti::Declaration>, std::vector<hilti::Statement>>> global_scope_items

// Spicy-only
%type <std::optional<hilti::ID>>                            opt_unit_field_id
%type <spicy::Engine>                                       opt_unit_field_engine opt_hook_engine
%type <spicy::Hook>                                         unit_hook
%type <std::vector<spicy::Hook>>                            opt_unit_item_hooks unit_hooks
%type <spicy::type::unit::Item>                             unit_item unit_variable unit_field unit_field_in_container unit_wide_hook unit_property unit_switch unit_sink
%type <std::vector<spicy::type::unit::Item>>                unit_items opt_unit_items
%type <spicy::type::unit::item::switch_::Case>              unit_switch_case
%type <std::vector<spicy::type::unit::item::switch_::Case>> unit_switch_cases
%type <std::pair<hilti::Type, std::optional<hilti::Expression>>> global_decl_type_and_init

%type <int64_t>  const_sint
%type <uint64_t> const_uint
%type <bool>     opt_skip opt_skip_

%%

// Magic states sent by the scanner to provide two separate entry points.
%token START_MODULE START_EXPRESSION;
%start start;

start         : START_MODULE module
              | START_EXPRESSION start_expr
              ;

start_expr    : expr                             { driver->setDestinationExpression(std::move($1)); }

module        : MODULE local_id ';'              { _docs.emplace_back(driver->docGetAndClear()); }
                global_scope_items               { auto m = hilti::Module($2, std::move($5.first), std::move($5.second), __loc__);
                                                   m.setDocumentation(_docs.back());
                                                   _docs.pop_back();
                                                   driver->setDestinationModule(m);
                                                 }
              ;

/* IDs */

local_id      : IDENT                            { std::string name($1);

                                                   if ( name.find('-') != std::string::npos)
                                                       hilti::logger().error(hilti::util::fmt("Invalid ID '%s': cannot contain '-'", name), __loc__.location());
                                                   if ( name.substr(0, 2) == "__" )
                                                       hilti::logger().error(hilti::util::fmt("Invalid ID '%s': cannot start with '__'", name), __loc__.location());

                                                   $$ = hilti::ID(std::move(name), __loc__);
                                                 }

scoped_id     : local_id                         { $$ = std::move($1); }
              | SCOPED_IDENT                     { $$ = hilti::ID($1, __loc__); }

dotted_id     : { driver->enableDottedIDMode(); }
                DOTTED_IDENT
                { driver->disableDottedIDMode(); } { $$ = hilti::ID($2, __loc__); }

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

type_decl     : opt_linkage TYPE scoped_id '='   { _docs.emplace_back(driver->docGetAndClear()); }
                type opt_attributes ';'          { if ( auto x = $6.isA<type::Unit>(); x && $7 && *$7 ) {
                                                       $6.as<type::Unit>().setAttributes(*$7);
                                                       $7 = {}; // don't associate with declaration
                                                       }

                                                   $$ = hilti::declaration::Type(std::move($3), std::move($6), std::move($7), std::move($1), __loc__);
                                                   $$.setDocumentation(_docs.back());
                                                   _docs.pop_back();
                                                 }

constant_decl : opt_linkage CONST scoped_id      { _docs.emplace_back(driver->docGetAndClear()); }
                '=' expr ';'                     { $$ = hilti::declaration::Constant($3, $6, $1, __loc__);
                                                   $$.setDocumentation(_docs.back());
                                                   _docs.pop_back();
                                                 }

              | opt_linkage CONST scoped_id      { _docs.emplace_back(driver->docGetAndClear()); }
                ':' type '=' expr ';'            { $$ = hilti::declaration::Constant($3, $6, $8, $1, __loc__);
                                                   $$.setDocumentation(_docs.back());
                                                   _docs.pop_back();
                                                 }
              ;

local_decl    : LOCAL scoped_id '=' expr ';'     { $$ = hilti::declaration::LocalVariable($2, $4, false, __loc__); }
              | LOCAL scoped_id ':' type ';'     { $$ = hilti::declaration::LocalVariable($2, $4, {}, false, __loc__); }
              | LOCAL scoped_id ':' type '=' expr ';'
                                                 { $$ = hilti::declaration::LocalVariable($2, $4, $6, false, __loc__); }
              ;

local_init_decl
              : LOCAL local_id ':' type '=' expr
                                                 { $$ = hilti::declaration::LocalVariable($2, $4, $6, false, __loc__); }
              | LOCAL local_id '=' expr
                                                 { $$ = hilti::declaration::LocalVariable($2, $4, false, __loc__); }
              ;

global_decl   : opt_linkage GLOBAL scoped_id     { _docs.emplace_back(driver->docGetAndClear()); }
                '=' expr ';'                     { $$ = hilti::declaration::GlobalVariable($3, $6, $1, __loc__);
                                                   $$.setDocumentation(_docs.back());
                                                   _docs.pop_back();
                                                 }

              | opt_linkage GLOBAL scoped_id     { _docs.emplace_back(driver->docGetAndClear()); }
                ':' global_decl_type_and_init    { $$ = hilti::declaration::GlobalVariable($3, $6.first, $6.second, $1, __loc__);
                                                   $$.setDocumentation(_docs.back());
                                                   _docs.pop_back();
                                                 }
              ;

global_decl_type_and_init
              : type ';'                         { $$ = std::make_pair($1, std::nullopt); }
              | type '=' expr ';'                { $$ = std::make_pair($1, $3); }

function_decl : opt_linkage FUNCTION opt_func_flavor opt_func_cc scoped_id '(' opt_func_params ')' opt_func_result opt_attributes
                                                 { _docs.emplace_back(driver->docGetAndClear()); }
                ';'                              {
                                                    auto ftype = hilti::type::Function($9, $7, $3, __loc__);
                                                    auto func = hilti::Function($5, std::move(ftype), {}, $4, $10, __loc__);
                                                    $$ = hilti::declaration::Function(std::move(func), $1, __loc__);
                                                    $$.setDocumentation(_docs.back());
                                                    _docs.pop_back();
                                                 }

              | opt_linkage FUNCTION opt_func_flavor opt_func_cc scoped_id '(' opt_func_params ')' opt_func_result opt_attributes
                                                 { _docs.emplace_back(driver->docGetAndClear()); }
                braced_block                     {
                                                    auto ftype = hilti::type::Function($9, $7, $3, __loc__);
                                                    auto func = hilti::Function($5, std::move(ftype), $12, $4, $10, __loc__);
                                                    $$ = hilti::declaration::Function(std::move(func), $1, __loc__);
                                                    $$.setDocumentation(_docs.back());
                                                    _docs.pop_back();
                                                 }
              ;

import_decl   : IMPORT local_id ';'              { $$ = hilti::declaration::ImportedModule(std::move($2), std::string(".spicy"), __loc__); }
              | IMPORT local_id FROM dotted_id ';' { $$ = hilti::declaration::ImportedModule(std::move($2), std::string(".spicy"), std::move($4), __loc__); }
              ;

property_decl : PROPERTY ';'                     { $$ = hilti::declaration::Property(ID(std::move($1)), __loc__); }
              | PROPERTY '=' expr ';'            { $$ = hilti::declaration::Property(ID(std::move($1)), std::move($3), __loc__); }
              | PROPERTY '=' base_type ';'       { $$ = hilti::declaration::Property(ID(std::move($1)), hilti::expression::Type_(std::move($3)), __loc__); }
              ;

hook_decl     : ON unit_hook_id unit_hook        { ID unit = $2.namespace_();
                                                   if ( unit.empty() )
                                                      error(@$, "hook requires unit namespace");

                                                   $$ = spicy::declaration::UnitHook(std::move($2), std::move($3), __loc__);
                                                 }
              ;

opt_linkage   : PUBLIC                           { $$ = hilti::declaration::Linkage::Public; }
              | PRIVATE                          { $$ = hilti::declaration::Linkage::Private; }
              | /* empty */                      { $$ = hilti::declaration::Linkage::Private; }

/* Function helpers */

opt_func_flavor : /* empty */                    { $$ = hilti::type::function::Flavor::Standard; }

opt_func_cc   : CSTRING                          { try {
                                                       $$ = hilti::function::calling_convention::from_string($1);
                                                   } catch ( std::out_of_range& e ) {
                                                       error(@$, "unknown calling convention");
                                                   }
                                                 }
              | /* empty */                      { $$ = hilti::function::CallingConvention::Standard; }


opt_func_params
              : func_params                      { $$ = std::move($1); }
              | /* empty */                      { $$ = std::vector<hilti::type::function::Parameter>{}; }

func_params   : func_params ',' func_param       { $$ = std::move($1); $$.push_back($3); }
              | func_param                       { $$ = std::vector<hilti::type::function::Parameter>{$1}; }

func_param    : opt_func_param_kind local_id ':' type opt_init_expression
                                                 { $$ = hilti::type::function::Parameter($2, $4, $1, $5, __loc__); }

func_result   : ':' type                         { $$ = hilti::type::function::Result(std::move($2), __loc__); }

opt_func_result : func_result                    { $$ = std::move($1); }
                | /* empty */                    { $$ = hilti::type::function::Result(hilti::type::void_, __loc__); }

opt_func_param_kind
              : INOUT                            { $$ = hilti::declaration::parameter::Kind::InOut; }
              | /* empty */                      { $$ = hilti::declaration::parameter::Kind::In; }
              ;

opt_init_expression : '=' expr                 { $$ = std::move($2); }
              | /* empty */                      { $$ = {}; }
              ;

/* Statements */

block         : braced_block                     { $$ = std::move($1); }
              | stmt                             { $$ = hilti::statement::Block({$1}, __loc__); }
              ;

braced_block  : '{' opt_stmts '}'                { $$ = hilti::statement::Block(std::move($2), __loc__); }

opt_stmts     : stmts                            { $$ = std::move($1); }
              | /* empty */                      { $$ = std::vector<hilti::Statement>{}; }

stmts         : stmts stmt                       { $$ = std::move($1); $$.push_back($2); }
              | stmt                             { $$ = std::vector<hilti::Statement>{std::move($1)}; }

stmt          : stmt_expr ';'                    { $$ = std::move($1); }
              | stmt_decl                        { $$ = std::move($1); }
              | ASSERT expr ';'                  { $$ = hilti::statement::Assert(std::move($2), {}, __loc__); }
              | ASSERT expr ':' expr ';'         { $$ = hilti::statement::Assert(std::move($2), std::move($4), __loc__); }
              | ASSERT_EXCEPTION expr ';'        { $$ = hilti::statement::Assert(hilti::statement::assert::Exception(), std::move($2), {}, {}, __loc__); }
              | ASSERT_EXCEPTION expr ':' expr ';'
                                                 { $$ = hilti::statement::Assert(hilti::statement::assert::Exception(), std::move($2), {}, std::move($4), __loc__); }
              | BREAK ';'                        { $$ = hilti::statement::Break(__loc__); }
              | CONTINUE ';'                     { $$ = hilti::statement::Continue(__loc__); }
              | FOR '(' local_id IN expr ')' block
                                                 { $$ = hilti::statement::For(std::move($3), std::move($5), std::move($7), __loc__); }
              | IF '(' expr ')' block opt_else_block
                                                 { $$ = hilti::statement::If(std::move($3), std::move($5), std::move($6), __loc__); }
              | IF '(' local_init_decl ')' block opt_else_block
                                                 { $$ = hilti::statement::If(std::move($3), {}, std::move($5), std::move($6), __loc__); }
              | IF '(' local_init_decl ';' expr ')' block opt_else_block
                                                 { $$ = hilti::statement::If(std::move($3), std::move($5), std::move($7), std::move($8), __loc__); }
              | PRINT opt_exprs ';'              { $$ = spicy::statement::Print(std::move($2), __loc__); }
              | RETURN ';'                       { $$ = hilti::statement::Return(__loc__); }
              | RETURN expr ';'                  { $$ = hilti::statement::Return(std::move($2), __loc__); }
              | STOP ';'                         { $$ = spicy::statement::Stop(__loc__); }
              | THROW expr ';'                   { $$ = hilti::statement::Throw(hilti::builder::exception(hilti::builder::typeByID("spicy_rt::ParseError"), $2, __loc__), __loc__); }
              | SWITCH '(' expr ')' '{' switch_cases '}'
                                                 { $$ = hilti::statement::Switch(std::move($3), std::move($6), __loc__); }
              | SWITCH '(' local_init_decl ')' '{' switch_cases '}'
                                                 { $$ = hilti::statement::Switch(std::move($3), std::move($6), __loc__); }
              | CONFIRM ';'                      { $$ = spicy::statement::Confirm(__loc__); }
              | REJECT_ ';'                      { $$ = spicy::statement::Reject(__loc__); }
              | WHILE '(' local_init_decl ';' expr ')' block
                                                 { $$ = hilti::statement::While(std::move($3), std::move($5), std::move($7), std::nullopt, __loc__); }
              | WHILE '(' expr ')' block
                                                 { $$ = hilti::statement::While(std::move($3), std::move($5), std::nullopt, __loc__); }
              | WHILE '(' local_init_decl ')' block
                                                 { $$ = hilti::statement::While(std::move($3), {}, std::move($5), std::nullopt, __loc__); }

              | ADD expr ';'                     { auto op = $2.tryAs<hilti::expression::UnresolvedOperator>();
                                                   if ( ! (op && op->kind() == hilti::operator_::Kind::Index) )
                                                        error(@$, "'add' must be used with index expression only");

                                                   auto expr = hilti::expression::UnresolvedOperator(hilti::operator_::Kind::Add, op->operands(), __loc__);
                                                   $$ = hilti::statement::Expression(std::move(expr), __loc__);
                                                 }

              | DELETE expr ';'                  { auto op = $2.tryAs<hilti::expression::UnresolvedOperator>();
                                                   if ( ! (op && op->kind() == hilti::operator_::Kind::Index) )
                                                        error(@$, "'delete' must be used with index expressions only");

                                                   auto expr = hilti::expression::UnresolvedOperator(hilti::operator_::Kind::Delete, op->operands(), __loc__);
                                                   $$ = hilti::statement::Expression(std::move(expr), __loc__);
                                                 }

              | UNSET expr ';'                   { auto op = $2.tryAs<hilti::expression::UnresolvedOperator>();
                                                   if ( ! (op && op->kind() == hilti::operator_::Kind::Member) )
                                                        error(@$, "'unset' must be used with member expressions only");

                                                   auto expr = hilti::expression::UnresolvedOperator(hilti::operator_::Kind::Unset, op->operands(), __loc__);
                                                   $$ = hilti::statement::Expression(std::move(expr), __loc__);
                                                 }

              ;

opt_else_block
              : ELSE block                       { $$ = std::move($2); }
              | /* empty */                      { $$ = {}; }

switch_cases  : switch_cases switch_case         { $$ = std::move($1); $$.push_back(std::move($2)); }
              | switch_case                      { $$ = std::vector<hilti::statement::switch_::Case>({ std::move($1) }); }

switch_case   : CASE exprs ':' block             { $$ = hilti::statement::switch_::Case(std::move($2), std::move($4), __loc__); }
              | DEFAULT ':' block                { $$ = hilti::statement::switch_::Case(hilti::statement::switch_::Default(), std::move($3), __loc__); }

stmt_decl     : local_decl                       { $$ = hilti::statement::Declaration($1, __loc__); }
              | type_decl                        { $$ = hilti::statement::Declaration($1, __loc__); }
              | constant_decl                    { $$ = hilti::statement::Declaration($1, __loc__); }
              ;

stmt_expr     : expr                             { $$ = hilti::statement::Expression($1, __loc__); }

/* Types */

base_type_no_ref
              : ANY                              { $$ = hilti::type::Any(__loc__); }
              | ADDRESS                          { $$ = hilti::type::Address(__loc__); }
              | BOOL                             { $$ = hilti::type::Bool(__loc__); }
              | BYTES                            { $$ = hilti::type::Bytes(__loc__); }
              | INTERVAL                         { $$ = hilti::type::Interval(__loc__); }
              | NETWORK                          { $$ = hilti::type::Network(__loc__); }
              | PORT                             { $$ = hilti::type::Port(__loc__); }
              | REAL                             { $$ = hilti::type::Real(__loc__); }
              | REGEXP                           { $$ = hilti::type::RegExp(__loc__); }
              | STREAM                           { $$ = hilti::type::Stream(__loc__); }
              | STRING                           { $$ = hilti::type::String(__loc__); }
              | TIME                             { $$ = hilti::type::Time(__loc__); }
              | VOID                             { $$ = hilti::type::void_; }

              | INT8                             { $$ = hilti::type::SignedInteger(8, __loc__); }
              | INT16                            { $$ = hilti::type::SignedInteger(16, __loc__); }
              | INT32                            { $$ = hilti::type::SignedInteger(32, __loc__); }
              | INT64                            { $$ = hilti::type::SignedInteger(64, __loc__); }
              | UINT8                            { $$ = hilti::type::UnsignedInteger(8, __loc__); }
              | UINT16                           { $$ = hilti::type::UnsignedInteger(16, __loc__); }
              | UINT32                           { $$ = hilti::type::UnsignedInteger(32, __loc__); }
              | UINT64                           { $$ = hilti::type::UnsignedInteger(64, __loc__); }

              | CONST_ITERATOR type_param_begin type type_param_end      { $$ = iteratorForType(std::move($3), true, __loc__); }
              | ITERATOR type_param_begin type type_param_end            { $$ = iteratorForType(std::move($3), false, __loc__); }
              | OPTIONAL type_param_begin type type_param_end            { $$ = hilti::type::Optional($3, __loc__); }
              | VIEW type_param_begin type type_param_end                { $$ = viewForType(std::move($3), __loc__); }

              | MAP type_param_begin type ',' type type_param_end        { $$ = hilti::type::Map(std::move($3), std::move($5), __loc__); }
              | SET type_param_begin type type_param_end                 { $$ = hilti::type::Set(std::move($3), __loc__); }
              | VECTOR type_param_begin type type_param_end              { $$ = hilti::type::Vector(std::move($3), __loc__); }

              | SINK                             { $$ = spicy::type::Sink(__loc__); }

              | LIBRARY_TYPE '(' CSTRING ')'     { $$ = hilti::type::Library(std::move($3), __loc__); }

              | tuple_type                       { $$ = std::move($1); }
              | struct_type                      { $$ = std::move($1); }
              | enum_type                        { $$ = std::move($1); }
              | bitfield_type                    { $$ = std::move($1); }
              | unit_type                        { $$ = std::move($1); }

              ;

/* We split this out from "base_type" because it can lead to ambigitious in some contexts. */
reference_type: type '&'                         { $$ = hilti::type::StrongReference(std::move($1), __loc__); }

base_type     : base_type_no_ref                 { $$ = std::move($1); }
                reference_type: type '&'         { $$ = hilti::type::StrongReference(std::move($1), __loc__); }
              ;

type          : base_type                        { $$ = std::move($1); }
              | reference_type                   { $$ = std::move($1); }
              | scoped_id                        { $$ = hilti::type::UnresolvedID(std::move($1)); }
              ;

type_param_begin:
              '<'
              { driver->disableExpressionMode(); }

type_param_end:
              '>'
              { driver->enableExpressionMode(); }

tuple_type    : TUPLE type_param_begin '*' type_param_end                { $$ = hilti::type::Tuple(hilti::type::Wildcard(), __loc__); }
              | TUPLE type_param_begin tuple_type_elems type_param_end   { $$ = hilti::type::Tuple(std::move($3), __loc__); }
              ;

tuple_type_elems
              : tuple_type_elems ',' tuple_type_elem
                                                 { $$ = std::move($1); $$.push_back(std::move($3)); }
              | tuple_type_elems ','             { $$ = std::move($1); }
              | tuple_type_elem                  { $$ = std::vector<type::tuple::Element>{ std::move($1) }; }
              ;

tuple_type_elem
              : type                             { $$ = type::tuple::Element(std::move($1)); }
              | local_id ':' type                { $$ = type::tuple::Element(std::move($1), std::move($3)); }
              ;

struct_type   : STRUCT '{' struct_fields '}'     { $$ = hilti::type::Struct(std::move($3), __loc__); }

struct_fields : struct_fields struct_field       { $$ = std::move($1); $$.push_back($2); }
              | /* empty */                      { $$ = std::vector<Declaration>{}; }

struct_field  : local_id ':' type opt_attributes ';' { $$ = hilti::declaration::Field(std::move($1), std::move($3), std::move($4), __loc__); }

enum_type     : ENUM '{' enum_labels '}'         { $$ = hilti::type::Enum(std::move($3), __loc__); }

enum_labels   : enum_labels ',' enum_label       { $$ = std::move($1); $$.push_back(std::move($3)); }
              | enum_labels ','                  { $$ = std::move($1); }
              | enum_label                       { $$ = std::vector<hilti::type::enum_::Label>(); $$.push_back(std::move($1)); }
              ;

enum_label    : local_id                         { $$ = hilti::type::enum_::Label(std::move($1), __loc__); }
              | local_id '=' CUINTEGER           { $$ = hilti::type::enum_::Label(std::move($1), $3, __loc__); }
              ;

bitfield_type : BITFIELD '(' CUINTEGER ')'
                                                 { _field_width = $3; }
                '{' opt_bitfield_bits '}'
                                                 { $$ = spicy::type::Bitfield($3, $7, __loc__); }

opt_bitfield_bits
              : bitfield_bits
                                                 { $$ = std::move($1); }
              | /* empty */                      { $$ = std::vector<spicy::type::bitfield::Bits>(); }

bitfield_bits
              : bitfield_bits bitfield_bits_spec
                                                 { $$ = std::move($1); $$.push_back(std::move($2));  }
              | bitfield_bits_spec               { $$ = std::vector<spicy::type::bitfield::Bits>(); $$.push_back(std::move($1)); }

bitfield_bits_spec
              : local_id ':' CUINTEGER DOTDOT CUINTEGER opt_attributes ';'
                                                 { $$ = spicy::type::bitfield::Bits(std::move($1), $3, $5, _field_width, std::move($6), __loc__); }
              | local_id ':' CUINTEGER opt_attributes ';'
                                                 { $$ = spicy::type::bitfield::Bits(std::move($1), $3, $3, _field_width, std::move($4), __loc__); }

/* --- Begin of Spicy units --- */

unit_type     : UNIT opt_unit_params '{' opt_unit_items '}'
                                                 { $$ = spicy::type::Unit(std::move($2), std::move($4), {}, __loc__); }

opt_unit_params
              : '(' opt_func_params ')'          { $$ = std::move($2); }
              | /* empty */                      { $$ = std::vector<hilti::type::function::Parameter>{}; }

unit_items    : unit_items unit_item             { $$ = std::move($1); $$.push_back(std::move($2)); }
              | unit_item                        { $$ = std::vector<spicy::type::unit::Item>(); $$.push_back($1); }

opt_unit_items: unit_items                       { $$ = std::move($1);}
              | /* empty */                      { $$ = std::vector<spicy::type::unit::Item>{}; }


unit_item     : unit_field                       { $$ = std::move($1); }
              | unit_variable                    { $$ = std::move($1); }
              | unit_wide_hook                   { $$ = std::move($1); }
              | unit_property                    { $$ = std::move($1); }
              | unit_sink                        { $$ = std::move($1); }
              | unit_switch                      { $$ = std::move($1); }
              ;


unit_variable : VAR local_id ':' type opt_init_expression opt_attributes ';'
                                                 { $$ = spicy::type::unit::item::Variable(std::move($2), std::move($4), std::move($5), std::move($6), __loc__); }

unit_sink     : SINK local_id opt_attributes ';' { $$ = spicy::type::unit::item::Sink(std::move($2), std::move($3), __loc__); }

unit_property : PROPERTY opt_attributes ';'      { $$ = type::unit::item::Property(ID(std::move($1)), std::move($2), false, __loc__); };
              | PROPERTY '=' expr opt_attributes';'
                                                 { $$ = type::unit::item::Property(ID(std::move($1)), std::move($3), std::move($4), false, __loc__); };
              | PROPERTY '=' base_type_no_ref ';'       { $$ = type::unit::item::Property(ID(std::move($1)), hilti::expression::Type_(std::move($3)), {}, false, __loc__); };


unit_field    : opt_unit_field_id opt_unit_field_engine opt_skip base_type opt_unit_field_repeat opt_attributes opt_unit_field_condition opt_unit_field_sinks opt_unit_item_hooks
                                                 {   if ( $4.isA<type::Vector>() )
                                                         error(@$, "vector<T> syntax is no longer supported for parsing sequences; use T[] instead.");
                                                     $$ = spicy::type::unit::item::UnresolvedField(std::move($1), std::move($4), std::move($2), $3, {}, std::move($5), std::move($8), std::move($6), std::move($7), std::move($9), __loc__);
                                                 }

              | opt_unit_field_id opt_unit_field_engine opt_skip unit_field_ctor opt_unit_field_repeat opt_attributes opt_unit_field_condition opt_unit_field_sinks opt_unit_item_hooks
                                                 { $$ = spicy::type::unit::item::UnresolvedField(std::move($1), std::move($4), std::move($2), $3, {}, std::move($5), std::move($8), std::move($6), std::move($7), std::move($9), __loc__); }

              | opt_unit_field_id opt_unit_field_engine opt_skip scoped_id  opt_unit_field_args opt_unit_field_repeat opt_attributes opt_unit_field_condition opt_unit_field_sinks opt_unit_item_hooks
                                                 { $$ = spicy::type::unit::item::UnresolvedField(std::move($1), std::move($4), std::move($2), $3, std::move($5), std::move($6), std::move($9), std::move($7), std::move($8), std::move($10), __loc__); }
              | opt_unit_field_id opt_unit_field_engine opt_skip '(' unit_field_in_container ')' opt_unit_field_repeat opt_attributes opt_unit_field_condition opt_unit_field_sinks opt_unit_item_hooks
                                                 { $$ = spicy::type::unit::item::UnresolvedField(std::move($1), std::move($5), std::move($2), $3, {}, std::move($7), std::move($10), std::move($8), std::move($9), std::move($11), __loc__); }

const_sint    : CUINTEGER                        { $$ = check_int64_range($1, true, __loc__); }
              | '+' CUINTEGER                    { $$ = check_int64_range($2, true, __loc__); }
              | '-' CUINTEGER                    { $$ = -check_int64_range($2, false, __loc__); }

const_uint    : CUINTEGER                        { $$ = $1; }
              | '+' CUINTEGER                    { $$ = $2; }

unit_field_ctor
              : ctor                             { $$ = std::move($1); }
              | UINT8 '(' const_uint ')'         { $$ = hilti::ctor::UnsignedInteger($3, 8, __loc__); }
              | UINT16 '(' const_uint ')'        { $$ = hilti::ctor::UnsignedInteger($3, 16, __loc__); }
              | UINT32 '(' const_uint ')'        { $$ = hilti::ctor::UnsignedInteger($3, 32, __loc__); }
              | UINT64 '(' const_uint ')'        { $$ = hilti::ctor::UnsignedInteger($3, 64, __loc__); }
              | INT8 '(' const_sint ')'          { $$ = hilti::ctor::SignedInteger($3, 8, __loc__); }
              | INT16 '(' const_sint ')'         { $$ = hilti::ctor::SignedInteger($3, 16, __loc__); }
              | INT32 '(' const_sint ')'         { $$ = hilti::ctor::SignedInteger($3, 32, __loc__); }
              | INT64 '(' const_sint ')'         { $$ = hilti::ctor::SignedInteger($3, 64, __loc__); }

unit_field_in_container
              : ctor opt_unit_field_args opt_attributes
                                                 { $$ = spicy::type::unit::item::UnresolvedField({}, std::move($1), {}, false, std::move($2), {}, {}, std::move($3), {}, {}, __loc__); }
              | scoped_id opt_unit_field_args opt_unit_field_repeat opt_attributes
                                                 { $$ = spicy::type::unit::item::UnresolvedField({}, std::move($1), {}, false, std::move($2), std::move($3), {}, std::move($4), {}, {}, __loc__); }
              | base_type opt_unit_field_repeat opt_unit_field_args opt_attributes
                                                 { $$ = spicy::type::unit::item::UnresolvedField({}, std::move($1), {}, false, std::move($3), std::move($2), {}, std::move($4), {}, {}, __loc__); }

unit_wide_hook : ON unit_hook_id unit_hook       { $$ = spicy::type::unit::item::UnitHook(std::move($2), std::move($3), __loc__); }

opt_unit_field_id
              : local_id                         { $$ = std::move($1); }
              | /* empty */                      { $$ = std::nullopt; }

opt_unit_field_engine
              : ':'                              { $$ = spicy::Engine::All; }
              | '<'                              { $$ = spicy::Engine::Parser; }
              | '>'                              { $$ = spicy::Engine::Composer; }
              | /* empty */                      { $$ = spicy::Engine::All; } /* Default */

opt_skip      :
              { driver->enableNewKeywordMode(); }
              opt_skip_
              { driver->disableNewKeywordMode(); $$ = $2; }

opt_skip_     :
                SKIP                             { $$ = true; }
              | /* empty */                      { $$ = false; }

opt_unit_field_args
              : '(' opt_exprs ')'                { $$ = std::move($2); }
              | /* empty */                      { $$ = std::vector<hilti::Expression>(); }

unit_field_repeat
              : '[' expr ']'                     { $$ = std::move($2); }
              | '[' ']'                          { $$ = hilti::builder::null(); }

opt_unit_field_repeat
              : unit_field_repeat                { $$ = std::move($1); }
              | /* empty */                      { $$ = {}; }

opt_unit_field_condition
              : IF '(' expr ')'                  { $$ = std::move($3); }
              | /* empty */                      { $$ = {}; }

opt_unit_field_sinks
              : ARROW exprs                      { $$ = std::move($2); }
              | /* empty */                      { $$ = std::vector<hilti::Expression>(); }

opt_unit_item_hooks
              : unit_hooks                       { $$ = std::move($1); }
              | ';'                              { $$ = std::vector<spicy::Hook>(); }

unit_hooks    : unit_hooks unit_hook             { $$ = std::move($1); $$.push_back(std::move($2)); }
              | unit_hook                        { $$ = std::vector<spicy::Hook>{std::move($1)}; }

unit_hook     : opt_unit_hook_params opt_unit_hook_attributes opt_hook_engine braced_block
                                                 { $$ = spicy::Hook(std::move($1), std::move($4), std::move($3), std::move($2), __loc__); }

opt_unit_hook_params
              : '(' opt_func_params ')'          { $$ = std::move($2); }
              | /* empty */                      { $$ = std::vector<hilti::type::function::Parameter>{}; }

opt_unit_hook_attributes
              : opt_unit_hook_attributes unit_hook_attribute
                                                 { $$ = hilti::AttributeSet::add($1, $2); }
              | /* empty */                      { $$ = {}; }

unit_hook_id: { driver->enableHookIDMode(); }
              HOOK_IDENT
              { driver->disableHookIDMode(); } { $$ = hilti::ID(hilti::util::replace($2, "%", "0x25_"), __loc__); }

unit_hook_attribute
              : FOREACH                          { $$ = hilti::Attribute("foreach", __loc__); }
              | PRIORITY '=' expr                { $$ = hilti::Attribute("priority", std::move($3), __loc__); }
              | PROPERTY                         { if ( $1 != "%debug" ) error(@$, "unexpected hook property, only %debug permitted");
                                                   $$ = hilti::Attribute("%debug", __loc__);
                                                 }

opt_hook_engine
              : HOOK_COMPOSE                     { $$ = spicy::Engine::Composer; }
              | HOOK_PARSE                       { $$ = spicy::Engine::Parser; }
              | /* empty */                      { $$ = spicy::Engine::Parser; } /* Default */

unit_switch   : SWITCH opt_unit_switch_expr '{' unit_switch_cases '}' opt_attributes opt_unit_field_condition ';'
                                                 { $$ = spicy::type::unit::item::Switch(std::move($2), std::move($4), spicy::Engine::All, std::move($7), {}, std::move($6), __loc__); }

opt_unit_switch_expr: '(' expr ')'               { $$ = std::move($2); }
              | /* empty */                      { $$ = {}; }

unit_switch_cases
              : unit_switch_cases unit_switch_case
                                                 { $$ = std::move($1); $$.push_back(std::move($2)); }
              | unit_switch_case                 { $$ = std::vector<spicy::type::unit::item::switch_::Case>(); $$.push_back(std::move($1)); }

unit_switch_case
              : exprs ARROW '{' unit_items '}'   { $$ = type::unit::item::switch_::Case($1, $4, __loc__); }
              | '*'   ARROW '{' unit_items '}'   { $$ = type::unit::item::switch_::Case($4, __loc__); }
              | exprs ARROW unit_item            { $$ = type::unit::item::switch_::Case($1, {$3}, __loc__); }
              | '*'   ARROW unit_item            { $$ = type::unit::item::switch_::Case(std::vector<type::unit::Item>{$3}, __loc__); }
              | ARROW unit_field                 { $$ = type::unit::item::switch_::Case($2, __loc__); }

/* --- End of Spicy units --- */

/* Expressions */

expr          :
              { driver->enableExpressionMode(); }
              expr_0
              { driver->disableExpressionMode(); }
                                                 { $$ = std::move($2); }
              ;

opt_exprs     : exprs                            { $$ = std::move($1); }
              | /* empty */                      { $$ = std::vector<Expression>(); }

exprs         : exprs ',' expr                   { $$ = std::move($1); $$.push_back(std::move($3)); }
              | expr                             { $$ = std::vector<Expression>{std::move($1)}; }

expr_0        : expr_1                           { $$ = std::move($1); }
              ;

expr_1        : expr_2 '=' expr_1                { $$ = hilti::expression::Assign(std::move($1), std::move($3), __loc__); }
              | expr_2 MINUSASSIGN expr_1        { $$ = hilti::expression::UnresolvedOperator(hilti::operator_::Kind::DifferenceAssign, {std::move($1), std::move($3)}, __loc__); }
              | expr_2 PLUSASSIGN expr_1         { $$ = hilti::expression::UnresolvedOperator(hilti::operator_::Kind::SumAssign, {std::move($1), std::move($3)}, __loc__); }
              | expr_2 TIMESASSIGN expr_1        { $$ = hilti::expression::UnresolvedOperator(hilti::operator_::Kind::MultipleAssign, {std::move($1), std::move($3)}, __loc__); }
              | expr_2 DIVIDEASSIGN expr_1       { $$ = hilti::expression::UnresolvedOperator(hilti::operator_::Kind::DivisionAssign, {std::move($1), std::move($3)}, __loc__); }
              | expr_2 '?' expr ':' expr         { $$ = hilti::expression::Ternary(std::move($1), std::move($3), std::move($5), __loc__); }
              | expr_2                           { $$ = std::move($1); }

expr_2        : expr_2 OR expr_3                 { $$ = hilti::expression::LogicalOr(std::move($1), std::move($3), __loc__); }
              | expr_3                           { $$ = std::move($1); }

expr_3        : expr_3 AND expr_4                { $$ = hilti::expression::LogicalAnd(std::move($1), std::move($3), __loc__); }
              | expr_4                           { $$ = std::move($1); }

expr_4        : expr_4 EQ expr_5                { $$ = hilti::expression::UnresolvedOperator(hilti::operator_::Kind::Equal, {std::move($1), std::move($3)}, __loc__); }
              | expr_4 NEQ expr_5                { $$ = hilti::expression::UnresolvedOperator(hilti::operator_::Kind::Unequal, {std::move($1), std::move($3)}, __loc__); }
              | expr_5                           { $$ = std::move($1); }

expr_5        : expr_5 '<' expr_6                { $$ = hilti::expression::UnresolvedOperator(hilti::operator_::Kind::Lower, {std::move($1), std::move($3)}, __loc__); }
              | expr_5 '>' expr_6                { $$ = hilti::expression::UnresolvedOperator(hilti::operator_::Kind::Greater, {std::move($1), std::move($3)}, __loc__); }
              | expr_5 GEQ expr_6                { $$ = hilti::expression::UnresolvedOperator(hilti::operator_::Kind::GreaterEqual, {std::move($1), std::move($3)}, __loc__); }
              | expr_5 LEQ expr_6                { $$ = hilti::expression::UnresolvedOperator(hilti::operator_::Kind::LowerEqual, {std::move($1), std::move($3)}, __loc__); }
              | expr_6                           { $$ = std::move($1); }

expr_6        : expr_6 '|' expr_7                { $$ = hilti::expression::UnresolvedOperator(hilti::operator_::Kind::BitOr, {std::move($1), std::move($3)}, __loc__); }
              | expr_7                           { $$ = std::move($1); }

expr_7        : expr_7 '^' expr_8                { $$ = hilti::expression::UnresolvedOperator(hilti::operator_::Kind::BitXor, {std::move($1), std::move($3)}, __loc__); }
              | expr_8                           { $$ = std::move($1); }

expr_8        : expr_8 '&' expr_9                { $$ = hilti::expression::UnresolvedOperator(hilti::operator_::Kind::BitAnd, {std::move($1), std::move($3)}, __loc__); }
              | expr_9                           { $$ = std::move($1); }

expr_9        : expr_9 SHIFTLEFT expr_a          { $$ = hilti::expression::UnresolvedOperator(hilti::operator_::Kind::ShiftLeft, {std::move($1), std::move($3)}, __loc__); }
              | expr_9 SHIFTRIGHT expr_a         { $$ = hilti::expression::UnresolvedOperator(hilti::operator_::Kind::ShiftRight, {std::move($1), std::move($3)}, __loc__); }
              | expr_a                           { $$ = std::move($1); }

expr_a        : expr_a '+' expr_b                { $$ = hilti::expression::UnresolvedOperator(hilti::operator_::Kind::Sum, {std::move($1), std::move($3)}, __loc__); }
              | expr_a '-' expr_b                { $$ = hilti::expression::UnresolvedOperator(hilti::operator_::Kind::Difference, {std::move($1), std::move($3)}, __loc__); }
              | expr_b                           { $$ = std::move($1); }

expr_b        : expr_b '%' expr_c                { $$ = hilti::expression::UnresolvedOperator(hilti::operator_::Kind::Modulo, {std::move($1), std::move($3)}, __loc__); }
              | expr_b '*' expr_c                { $$ = hilti::expression::UnresolvedOperator(hilti::operator_::Kind::Multiple, {std::move($1), std::move($3)}, __loc__); }
              | expr_b '/' expr_c                { $$ = hilti::expression::UnresolvedOperator(hilti::operator_::Kind::Division, {std::move($1), std::move($3)}, __loc__); }
              | expr_b POW expr_c                { $$ = hilti::expression::UnresolvedOperator(hilti::operator_::Kind::Power, {std::move($1), std::move($3)}, __loc__); }
              | expr_c                           { $$ = std::move($1); }

expr_c        : '!' expr_c                       { $$ = hilti::expression::LogicalNot(std::move($2), __loc__); }
              | '*' expr_c                       { $$ = hilti::expression::UnresolvedOperator(hilti::operator_::Kind::Deref, {std::move($2)}, __loc__); }
              | '~' expr_c                       { $$ = hilti::expression::UnresolvedOperator(hilti::operator_::Kind::Negate, {std::move($2)}, __loc__); }
              | '|' expr_c '|'                   { $$ = hilti::expression::UnresolvedOperator(hilti::operator_::Kind::Size, {std::move($2)}, __loc__); }
              | MINUSMINUS expr_c                { $$ = hilti::expression::UnresolvedOperator(hilti::operator_::Kind::DecrPrefix, {std::move($2)}, __loc__); }
              | PLUSPLUS expr_c                  { $$ = hilti::expression::UnresolvedOperator(hilti::operator_::Kind::IncrPrefix, {std::move($2)}, __loc__); }
              | expr_d                           { $$ = std::move($1); }

expr_d        : expr_d '(' opt_exprs ')'         { $$ = hilti::expression::UnresolvedOperator(hilti::operator_::Kind::Call, {std::move($1), hilti::expression::Ctor(hilti::ctor::Tuple(std::move($3), __loc__))}, __loc__); }
              | expr_d '.' member_expr           { $$ = hilti::expression::UnresolvedOperator(hilti::operator_::Kind::Member, {std::move($1), std::move($3)}, __loc__); }
              | expr_d '.' member_expr '(' opt_exprs ')' { $$ = hilti::expression::UnresolvedOperator(hilti::operator_::Kind::MemberCall, {std::move($1), std::move($3), hilti::expression::Ctor(hilti::ctor::Tuple(std::move($5), __loc__))}, __loc__); }
              | expr_d '[' expr ']'              { $$ = hilti::expression::UnresolvedOperator(hilti::operator_::Kind::Index, {std::move($1), std::move($3)}, __loc__); }
              | expr_d HASATTR member_expr       { $$ = hilti::expression::UnresolvedOperator(hilti::operator_::Kind::HasMember, {std::move($1), std::move($3)}, __loc__); }
              | expr_d IN expr_d                 { $$ = hilti::expression::UnresolvedOperator(hilti::operator_::Kind::In, {std::move($1), std::move($3)}, __loc__); }
              | expr_d NOT_IN expr_d             { $$ = hilti::expression::LogicalNot(hilti::expression::UnresolvedOperator(hilti::operator_::Kind::In, {std::move($1), std::move($3)}, __loc__)); }
              | expr_d MINUSMINUS                { $$ = hilti::expression::UnresolvedOperator(hilti::operator_::Kind::DecrPostfix, {std::move($1)}, __loc__); }
              | expr_d PLUSPLUS                  { $$ = hilti::expression::UnresolvedOperator(hilti::operator_::Kind::IncrPostfix, {std::move($1)}, __loc__); }
              | expr_d TRYATTR member_expr       { $$ = hilti::expression::UnresolvedOperator(hilti::operator_::Kind::TryMember, {std::move($1), std::move($3)}, __loc__); }
              | expr_e                           { $$ = std::move($1); }

expr_e        : CAST type_param_begin type type_param_end '(' expr ')'   { $$ = hilti::expression::UnresolvedOperator(hilti::operator_::Kind::Cast, {std::move($6), hilti::expression::Type_(std::move($3))}, __loc__); }
              | PACK tuple_expr                  { $$ = hilti::expression::UnresolvedOperator(hilti::operator_::Kind::Pack, {std::move($2)}, __loc__); }
              | UNPACK type_param_begin type type_param_end tuple_expr   { $$ = hilti::expression::UnresolvedOperator(hilti::operator_::Kind::Unpack, {hilti::expression::Type_(std::move($3)), std::move($5), hilti::expression::Ctor(hilti::ctor::Bool(true), __loc__)}, __loc__); }
              | BEGIN_ '(' expr ')'              { $$ = hilti::expression::UnresolvedOperator(hilti::operator_::Kind::Begin, {std::move($3)}, __loc__); }
              | END_ '(' expr ')'                { $$ = hilti::expression::UnresolvedOperator(hilti::operator_::Kind::End, {std::move($3)}, __loc__); }
              | NEW ctor                         { $$ = hilti::expression::UnresolvedOperator(hilti::operator_::Kind::New, {hilti::expression::Ctor(std::move($2), __loc__), hilti::expression::Ctor(hilti::ctor::Tuple({}, __loc__))}, __loc__); }
              | NEW scoped_id                    { $$ = hilti::expression::UnresolvedOperator(hilti::operator_::Kind::New, {hilti::expression::UnresolvedID(std::move($2), __loc__), hilti::expression::Ctor(hilti::ctor::Tuple({}, __loc__))}, __loc__); }
              | NEW scoped_id '(' opt_exprs ')'  { $$ = hilti::expression::UnresolvedOperator(hilti::operator_::Kind::New, {hilti::expression::UnresolvedID(std::move($2), __loc__), hilti::expression::Ctor(hilti::ctor::Tuple(std::move($4), __loc__))}, __loc__); }
              | expr_f                           { $$ = std::move($1); }

expr_f        : ctor                             { $$ = hilti::expression::Ctor(std::move($1), __loc__); }
              | ctor_expr                        { $$ = std::move($1); }
              | '-' expr_f                       { $$ = hilti::expression::UnresolvedOperator(hilti::operator_::Kind::SignNeg, {std::move($2)}, __loc__); }
              | '[' expr FOR local_id IN expr ']'
                                                 { $$ = hilti::expression::ListComprehension(std::move($6), std::move($2), std::move($4), {},  __loc__); }
              | '[' expr FOR local_id IN expr IF expr ']'
                                                 { $$ = hilti::expression::ListComprehension(std::move($6), std::move($2), std::move($4), std::move($8),  __loc__); }
              | expr_g                           { $$ = std::move($1); }

expr_g        : '(' expr ')'                     { $$ = hilti::expression::Grouping(std::move($2)); }
              | scoped_id                        { $$ = hilti::expression::UnresolvedID(std::move($1), __loc__); }
              | DOLLARDOLLAR                     { $$ = hilti::expression::UnresolvedID(std::move("__dd"), __loc__);}
              | DOLLAR_NUMBER                    { // $N -> $@[N] (with $@ being available internally only, not exposed to users)
                                                   auto captures = hilti::expression::Keyword(hilti::expression::keyword::Kind::Captures, hilti::builder::typeByID("hilti::Captures"), __loc__);
                                                   auto index = hilti::expression::Ctor(hilti::ctor::UnsignedInteger($1, 64, __loc__), __loc__);
                                                   $$ = hilti::expression::UnresolvedOperator(hilti::operator_::Kind::Index, {std::move(captures), std::move(index)}, __loc__);
                                                 }

member_expr   : local_id                         { $$ = hilti::expression::Member(std::move($1), __loc__); }

/* Constants */

ctor          : CADDRESS                         { $$ = hilti::ctor::Address(hilti::ctor::Address::Value($1), __loc__); }
              | CADDRESS '/' CUINTEGER           { $$ = hilti::ctor::Network(hilti::ctor::Network::Value($1, $3), __loc__); }
              | CBOOL                            { $$ = hilti::ctor::Bool($1, __loc__); }
              | CBYTES                           { $$ = hilti::ctor::Bytes(std::move($1), __loc__); }
              | CPORT                            { $$ = hilti::ctor::Port(hilti::ctor::Port::Value($1), __loc__); }
              | CNULL                            { $$ = hilti::ctor::Null(__loc__); }
              | CSTRING                          { $$ = hilti::ctor::String($1, __loc__); }
              | CUINTEGER                        { $$ = hilti::ctor::UnsignedInteger($1, 64, __loc__); }
              | '+' CUINTEGER                    { if ( $2 > static_cast<uint64_t>(std::numeric_limits<int64_t>::max()) )
                                                    hilti::logger().error("integer constant out of range", __loc__.location());

                                                   $$ = hilti::ctor::SignedInteger($2, 64, __loc__);
                                                 }
              | CUREAL                           { $$ = hilti::ctor::Real($1, __loc__); }
              | '+' CUREAL                       { $$ = hilti::ctor::Real($2, __loc__);; }

              /* There are more here that we could move into ctor_expr and have them use namedCtor.
                 But not sure if that'd change much so leaving here for now.
              */
              | OPTIONAL '(' expr ')'            { $$ = hilti::ctor::Optional(std::move($3), __loc__); }
              | list                             { $$ = std::move($1); }
              | map                              { $$ = std::move($1); }
              | regexp                           { $$ = std::move($1); }
              | set                              { $$ = std::move($1); }
              | struct_                          { $$ = std::move($1); }
              | tuple                            { $$ = std::move($1); }
              | vector                           { $$ = std::move($1); }
              ;

ctor_expr     : INTERVAL '(' expr ')'            { $$ = hilti::builder::namedCtor("interval", { std::move($3) }, __loc__); }
              | INTERVAL_NS '(' expr ')'         { $$ = hilti::builder::namedCtor("interval_ns", { std::move($3) }, __loc__); }
              | TIME '(' expr ')'                { $$ = hilti::builder::namedCtor("time", { std::move($3) }, __loc__); }
              | TIME_NS '(' expr ')'             { $$ = hilti::builder::namedCtor("time_ns", { std::move($3) }, __loc__); }
              | STREAM '(' expr ')'              { $$ = hilti::builder::namedCtor("stream", { std::move($3) }, __loc__); }
              | INT8 '(' expr ')'                { $$ = hilti::builder::namedCtor("int8", { std::move($3) }, __loc__); }
              | INT16 '(' expr ')'               { $$ = hilti::builder::namedCtor("int16", { std::move($3) }, __loc__); }
              | INT32 '(' expr ')'               { $$ = hilti::builder::namedCtor("int32", { std::move($3) }, __loc__); }
              | INT64 '(' expr ')'               { $$ = hilti::builder::namedCtor("int64", { std::move($3) }, __loc__); }
              | UINT8 '(' expr ')'               { $$ = hilti::builder::namedCtor("uint8", { std::move($3) }, __loc__); }
              | UINT16 '(' expr ')'              { $$ = hilti::builder::namedCtor("uint16", { std::move($3) }, __loc__); }
              | UINT32 '(' expr ')'              { $$ = hilti::builder::namedCtor("uint32", { std::move($3) }, __loc__); }
              | UINT64 '(' expr ')'              { $$ = hilti::builder::namedCtor("uint64", { std::move($3) }, __loc__); }
              | PORT '(' expr ',' expr ')'       { $$ = hilti::builder::namedCtor("port", {std::move($3), std::move($5)}, __loc__); }
              ;

tuple         : '(' opt_tuple_elems1 ')'         { $$ = hilti::ctor::Tuple(std::move($2), __loc__); }
              | TUPLE '(' opt_exprs ')'          { $$ = hilti::ctor::Tuple(std::move($3), __loc__); }

opt_tuple_elems1
              : tuple_elem                       { $$ = std::vector<hilti::Expression>{std::move($1)}; }
              | tuple_elem ',' opt_tuple_elems2  { $$ = std::vector<hilti::Expression>{std::move($1)}; $$.insert($$.end(), $3.begin(), $3.end()); }
              | /* empty */                      { $$ = std::vector<hilti::Expression>(); }

opt_tuple_elems2
              : tuple_elem                       { $$ = std::vector<hilti::Expression>{ std::move($1)}; }
              | tuple_elem ',' opt_tuple_elems2  { $$ = std::vector<hilti::Expression>{std::move($1)}; $$.insert($$.end(), $3.begin(), $3.end()); }
              | tuple_elem                       { $$ = std::vector<hilti::Expression>{ std::move($1)}; }
              | /* empty */                      { $$ = std::vector<hilti::Expression>(); }


tuple_elem    : expr                             { $$ = std::move($1); }
              | NONE                             { $$ = hilti::expression::Ctor(hilti::ctor::Null(__loc__), __loc__); }

tuple_expr    : tuple                            { $$ = hilti::expression::Ctor(std::move($1), __loc__); }

list          : '[' opt_exprs ']'                { $$ = hilti::ctor::List(std::move($2), __loc__); }
              | LIST '(' opt_exprs ')'           { $$ = hilti::ctor::List(std::move($3), __loc__); }
              | LIST type_param_begin type type_param_end '(' opt_tuple_elems1 ')'
                                                 { $$ = hilti::ctor::List(std::move($3), std::move($6), __loc__); }

vector        : VECTOR '(' opt_exprs ')'         { $$ = hilti::ctor::Vector(std::move($3), __loc__); }
              | VECTOR type_param_begin type type_param_end '(' opt_tuple_elems1 ')'
                                                 { $$ = hilti::ctor::Vector(std::move($3), std::move($6), __loc__); }

set           : SET '(' opt_exprs ')'            { $$ = hilti::ctor::Set(std::move($3), __loc__); }
              | SET type_param_begin type type_param_end '(' opt_tuple_elems1 ')'
                                                 { $$ = hilti::ctor::Set(std::move($3), std::move($6), __loc__); }

map           : MAP '(' opt_map_elems ')'        { $$ = hilti::ctor::Map(std::move($3), __loc__); }
              | MAP type_param_begin type ',' type type_param_end '(' opt_map_elems ')'
                                                 { $$ = hilti::ctor::Map(std::move($3), std::move($5), std::move($8), __loc__); }

struct_       : '[' struct_elems ']'             { $$ = hilti::ctor::Struct(std::move($2), __loc__); }
              /* We don't allow empty structs, we parse that as empty vectors instead. */

struct_elems  : struct_elems ',' struct_elem     { $$ = std::move($1); $$.push_back($3); }
              | struct_elem                      { $$ = std::vector<hilti::ctor::struct_::Field>{ std::move($1) }; }

struct_elem   : DOLLAR_IDENT '=' expr            { $$ = hilti::ctor::struct_::Field(hilti::ID(std::move($1)), std::move($3)); }

regexp        : re_patterns                      { $$ = hilti::ctor::RegExp(std::move($1), {}, __loc__); }

re_patterns   : re_patterns '|' re_pattern_constant
                                                 { $$ = $1; $$.push_back(std::move($3)); }
              | re_pattern_constant              { $$ = std::vector<std::string>{std::move($1)}; }

re_pattern_constant
              : '/' { driver->enablePatternMode(); } CREGEXP { driver->disablePatternMode(); } '/'
                                                 { $$ = std::move($3); }

opt_map_elems : map_elems                        { $$ = std::move($1); }
              | /* empty */                      { $$ = std::vector<hilti::ctor::map::Element>(); }

map_elems     : map_elems ',' map_elem           { $$ = std::move($1); $$.push_back(std::move($3)); }
              | map_elem                         { $$ = std::vector<hilti::ctor::map::Element>(); $$.push_back(std::move($1)); }

map_elem      : expr ':' expr                    { $$ = hilti::ctor::map::Element($1, $3); }

/* Attributes */

attribute     : ATTRIBUTE                       { $$ = hilti::Attribute(std::move($1), __loc__); }
              | ATTRIBUTE '=' expr              { $$ = hilti::Attribute(std::move($1), std::move($3), __loc__); }

opt_attributes
              : opt_attributes attribute        { $$ = hilti::AttributeSet::add($1, $2); }
              | /* empty */                     { $$ = {}; }

%%

void spicy::detail::parser::Parser::error(const Parser::location_type& l, const std::string& m) {
    driver->error(m, toMeta(l));
}
