/* Copyright (c) 2020 by the Zeek Project. See LICENSE for details. */

%skeleton "lalr1.cc"                          /*  -*- C++ -*- */
%require "3.4"
%defines

%{
namespace hilti { namespace detail { class Parser; } }

#include <hilti/compiler/detail/parser/driver.h>

%}

%locations
%initial-action
{
    @$.begin.filename = @$.end.filename = driver->currentFile();
};

%parse-param {class Driver* driver}
%lex-param   {class Driver* driver}

%define api.namespace {hilti::detail::parser}
%define api.parser.class {Parser}
%define parse.error verbose

%debug
%verbose

%glr-parser
%expect 102
%expect-rr 178

%union {}
%{

#include <hilti/compiler/detail/parser/scanner.h>

#undef yylex
#define yylex driver->scanner()->lex

static hilti::Meta toMeta(hilti::detail::parser::location l) {
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

#define __loc__ toMeta(yylhs.location)

%}

%token <str>       IDENT          "identifier"
%token <str>       SCOPED_IDENT   "scoped identifier"
%token <str>       DOTTED_IDENT   "dotted identifier"
%token <str>       ATTRIBUTE      "attribute"
%token <str>       PROPERTY       "property"

%token <str>       CSTRING        "string value"
%token <str>       CBYTES         "bytes value"
%token <str>       CREGEXP        "regular expression value"
%token <str>       CADDRESS       "address value"
%token <str>       CPORT          "port value"
%token <real>      CUREAL         "real value"
%token <uint>      CUINTEGER      "unsigned integer value"
%token <bool_>     CBOOL          "bool value"

%token             EOD 0            "<end of input>"

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
%token FILE "file"
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
%token INTERVAL "interval"
%token IOSRC "iosrc"
%token ITERATOR "iterator"
%token CONST_ITERATOR "const_iterator"
%token LEQ "<="
%token LIBRARY_TYPE "library type"
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
%token OPTIONAL "optional"
%token OR "||"
%token OVERLAY "overlay"
%token PLUSASSIGN "+="
%token PLUSPLUS "++"
%token PORT "port"
%token POW "**"
%token PRIVATE "private"
%token PUBLIC "public"
%token STRONG_REF "strong_ref"
%token REGEXP "regexp"
%token RESULT "result"
%token RETURN "return"
%token SCOPE "scope"
%token SELF "self"
%token SET "set"
%token SHIFTLEFT "<<"
%token SHIFTRIGHT ">>"
%token STREAM "stream"
%token STRING "string"
%token STRUCT "struct"
%token SWITCH "switch"
%token TIME "time"
%token TIMER "timer"
%token TIMERMGR "timer_mgr"
%token TIMESASSIGN "*="
%token THROW "throw"
%token TRY "try"
%token TRYATTR ".?"
%token TUPLE "tuple"
%token TYPE "type"
%token UINT "uint"
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

%type <id>                          local_id scoped_id dotted_id
%type <declaration>                 local_decl local_init_decl global_decl type_decl import_decl constant_decl function_decl global_scope_decl property_decl
%type <decls_and_stmts>             global_scope_items
%type <type>                        base_type_no_attrs base_type type function_type tuple_type struct_type enum_type union_type
%type <ctor>                        ctor tuple struct_ list regexp map set
%type <expression>                  expr tuple_elem tuple_expr member_expr expr_0 expr_1 expr_2 expr_3 expr_4 expr_5 expr_6 expr_7 expr_8 expr_9 expr_a expr_b expr_c expr_d expr_e expr_f expr_g
%type <expressions>                 opt_tuple_elems1 opt_tuple_elems2 exprs opt_exprs opt_type_arguments
%type <opt_expression>              opt_func_default_expr
%type <function>                    function_with_body function_without_body
%type <function_parameter>          func_param
%type <function_parameter_kind>     opt_func_param_kind
%type <function_result>             func_result
%type <function_flavor>             func_flavor opt_func_flavor
%type <function_calling_convention> opt_func_cc
%type <linkage>                     opt_linkage
%type <function_parameters>         func_params opt_func_params opt_struct_params
%type <statement>                   stmt stmt_decl stmt_expr block braced_block
%type <statements>                  stmts opt_stmts
%type <opt_statement>               opt_else_block
%type <attribute>                   attribute
%type <opt_attributes>              opt_attributes
%type <tuple_type_elem>             tuple_type_elem
%type <tuple_type_elems>            tuple_type_elems
%type <struct_field>                struct_field
%type <struct_fields>               struct_fields
%type <struct_elems>                struct_elems
%type <struct_elem>                 struct_elem
%type <union_field>                 union_field
%type <union_fields>                union_fields opt_union_fields
%type <map_elems>                   map_elems opt_map_elems
%type <map_elem>                    map_elem
%type <enum_label>                  enum_label
%type <enum_labels>                 enum_labels
%type <strings>                     re_patterns
%type <str>                         re_pattern_constant
%type <switch_case>                 switch_case
%type <switch_cases>                switch_cases
%type <try_catch>                   try_catch
%type <try_catches>                 try_catches
%type <type_flags>                  opt_type_flags /* type_flag */
%type <real>                        const_real
%type <sint>                        const_sint
%type <uint>                        const_uint

%%

%start module;

module        : MODULE local_id '{'
                global_scope_items '}'           { auto m = hilti::Module($2, std::move($4.first), std::move($4.second), __loc__);
                                                   driver->setDestinationModule(std::move(m));
                                                 }
              ;

/* IDs */

local_id      : IDENT                            { std::string name($1);

                                                   if (name.find('-') != std::string::npos)
                                                       hilti::logger().error(util::fmt("Invalid ID '%s': cannot contain '-'", name), __loc__.location());
                                                   if (name.substr(0, 2) == "__")
                                                       hilti::logger().error(util::fmt("Invalid ID '%s': cannot start with '__'", name), __loc__.location());

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
              | /* empty */                      { }
              ;

global_scope_decl
              : type_decl                        { $$ = std::move($1); }
              | constant_decl                    { $$ = std::move($1); }
              | global_decl                      { $$ = std::move($1); }
              | function_decl                    { $$ = std::move($1); }
              | import_decl                      { $$ = std::move($1); }
              | property_decl                    { $$ = std::move($1); }

type_decl     : opt_linkage TYPE scoped_id '=' type opt_attributes ';'
                                                 { $$ = hilti::declaration::Type(std::move($3), std::move($5), std::move($6), std::move($1), __loc__); }

constant_decl : opt_linkage CONST scoped_id '=' expr ';'
                                                 { $$ = hilti::declaration::Constant($3, $5, $1, __loc__); }

local_decl    : LOCAL local_id '=' expr ';'     { $$ = hilti::declaration::LocalVariable($2, $4.type(), $4, false, __loc__); }
              | LOCAL type local_id opt_type_arguments';' { $$ = hilti::declaration::LocalVariable($3, $2, $4, {}, false, __loc__); }
              | LOCAL type local_id '=' expr ';'
                                                 { $$ = hilti::declaration::LocalVariable($3, $2, $5, false, __loc__); }
              | LOCAL AUTO local_id '=' expr ';'
                                                 { $$ = hilti::declaration::LocalVariable($3, $5, false, __loc__); }
              ;

local_init_decl
              : LOCAL type local_id '=' expr
                                                 { $$ = hilti::declaration::LocalVariable($3, $2, $5, false, __loc__); }
              | LOCAL AUTO local_id '=' expr
                                                 { $$ = hilti::declaration::LocalVariable($3, $5, false, __loc__); }
              ;

global_decl   : opt_linkage GLOBAL scoped_id '=' expr ';'
                                                 { $$ = hilti::declaration::GlobalVariable($3, $5.type(), $5, $1, __loc__); }
              | opt_linkage GLOBAL type scoped_id opt_type_arguments ';'
                                                 { $$ = hilti::declaration::GlobalVariable($4, $3, $5, {}, $1, __loc__); }
              | opt_linkage GLOBAL type scoped_id '=' expr ';'
                                                 { $$ = hilti::declaration::GlobalVariable($4, $3, $6, $1, __loc__); }
              | opt_linkage GLOBAL AUTO scoped_id '=' expr ';'
                                                 { $$ = hilti::declaration::GlobalVariable($4, $6, $1, __loc__); }
              ;

opt_type_arguments
              : '(' opt_exprs ')'                { $$ = std::move($2); }
              | /* empty */                      { $$ = std::vector<Expression>{}; }

function_decl : opt_linkage FUNCTION function_with_body
                                                 { $$ = hilti::declaration::Function($3, $1, __loc__); }
              | METHOD function_with_body        { $$ = hilti::declaration::Function($2, hilti::declaration::Linkage::Struct, __loc__); }
              | DECLARE opt_linkage function_without_body ';'
                                                 { $$ = hilti::declaration::Function($3, $2, __loc__); }
              ;

import_decl   : IMPORT local_id ';'              { $$ = hilti::declaration::ImportedModule(std::move($2), std::string(".hlt"), __loc__); }
              | IMPORT local_id FROM dotted_id ';' { $$ = hilti::declaration::ImportedModule(std::move($2), std::string(".hlt"), std::move($4), __loc__); }
              ;


property_decl : PROPERTY ';'                     { $$ = hilti::declaration::Property(ID(std::move($1)), __loc__); }
              | PROPERTY '=' expr ';'            { $$ = hilti::declaration::Property(ID(std::move($1)), std::move($3), __loc__); }

opt_linkage   : PUBLIC                           { $$ = hilti::declaration::Linkage::Public; }
              | PRIVATE                          { $$ = hilti::declaration::Linkage::Private; }
              | INIT                             { $$ = hilti::declaration::Linkage::Init; }
              | /* empty */                      { $$ = hilti::declaration::Linkage::Private; }

/* Functions */

function_with_body
              : opt_func_flavor opt_func_cc func_result scoped_id '(' opt_func_params ')' opt_attributes braced_block
                                                 {
                                                    auto ftype = hilti::type::Function($3, $6, $1, __loc__);
                                                    $$ = hilti::Function($4, std::move(ftype), $9, $2, $8, __loc__);
                                                 }

function_without_body
              : opt_func_flavor opt_func_cc func_result scoped_id '(' opt_func_params ')' opt_attributes
                                                 {
                                                    auto ftype = hilti::type::Function($3, $6, $1, __loc__);
                                                    $$ = hilti::Function($4, std::move(ftype), {}, $2, $8, __loc__);
                                                 }

opt_func_flavor : func_flavor                    { $$ = $1; }
                | /* empty */                    { $$ = hilti::type::function::Flavor::Standard; }

func_flavor     : METHOD                         { $$ = hilti::type::function::Flavor::Method; }
                | HOOK                           { $$ = hilti::type::function::Flavor::Hook; }

opt_func_cc     : EXTERN                         { $$ = hilti::function::CallingConvention::Extern; }
                | /* empty */                    { $$ = hilti::function::CallingConvention::Standard; }


opt_func_params : func_params                    { $$ = std::move($1); }
               | /* empty */                     { $$ = std::vector<hilti::type::function::Parameter>{}; }

func_params : func_params ',' func_param { $$ = std::move($1); $$.push_back($3); }
                | func_param                     { $$ = std::vector<hilti::type::function::Parameter>{$1}; }

func_param      : opt_func_param_kind type local_id opt_func_default_expr
                                                 { $$ = hilti::type::function::Parameter($3, $2, $1, $4, __loc__); }

func_result   : type                             { $$ = hilti::type::function::Result(std::move($1), __loc__); }

opt_func_param_kind
              : COPY                             { $$ = hilti::declaration::parameter::Kind::Copy; }
              | INOUT                            { $$ = hilti::declaration::parameter::Kind::InOut; }
              | /* empty */                      { $$ = hilti::declaration::parameter::Kind::In; }
              ;

opt_func_default_expr : '=' expr                 { $$ = std::move($2); }
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
              | RETURN ';'                       { $$ = hilti::statement::Return(__loc__); }
              | RETURN expr ';'                  { $$ = hilti::statement::Return(std::move($2), __loc__); }
              | THROW expr ';'                   { $$ = hilti::statement::Throw(std::move($2), __loc__); }
              | THROW  ';'                       { $$ = hilti::statement::Throw(__loc__); }
              | YIELD ';'                        { $$ = hilti::statement::Yield(__loc__); }
              | BREAK ';'                        { $$ = hilti::statement::Break(__loc__); }
              | CONTINUE ';'                     { $$ = hilti::statement::Continue(__loc__); }
              | IF '(' expr ')' block opt_else_block
                                                 { $$ = hilti::statement::If(std::move($3), std::move($5), std::move($6), __loc__); }
              | IF '(' local_init_decl ')' block opt_else_block
                                                 { $$ = hilti::statement::If(std::move($3), {}, std::move($5), std::move($6), __loc__); }
              | IF '(' local_init_decl ';' expr ')' block opt_else_block
                                                 { $$ = hilti::statement::If(std::move($3), std::move($5), std::move($7), std::move($8), __loc__); }
              | WHILE '(' local_init_decl ';' expr ')' block opt_else_block
                                                 { $$ = hilti::statement::While(std::move($3), std::move($5), std::move($7), std::move($8), __loc__); }
              | WHILE '(' expr ')' block opt_else_block
                                                 { $$ = hilti::statement::While(std::move($3), std::move($5), std::move($6), __loc__); }
              | WHILE '(' local_init_decl ')' block opt_else_block
                                                 { $$ = hilti::statement::While(std::move($3), {}, std::move($5), std::move($6), __loc__); }
              | FOR '(' local_id IN expr ')' block
                                                 { $$ = hilti::statement::For(std::move($3), std::move($5), std::move($7), __loc__); }
              | SWITCH '(' expr ')' '{' switch_cases '}'
                                                 { $$ = hilti::statement::Switch(std::move($3), std::move($6), __loc__); }
              | SWITCH '(' local_init_decl ')' '{' switch_cases '}'
                                                 { $$ = hilti::statement::Switch($3, expression::UnresolvedID($3.as<declaration::LocalVariable>().id()), std::move($6), __loc__); }
              | TRY block try_catches
                                                 { $$ = hilti::statement::Try(std::move($2), std::move($3), __loc__); }
              | ASSERT expr ';'                  { $$ = hilti::statement::Assert(std::move($2), {}, __loc__); }
              | ASSERT expr ':' expr ';'         { $$ = hilti::statement::Assert(std::move($2), std::move($4), __loc__); }
              | ASSERT_EXCEPTION expr ';'        { $$ = hilti::statement::Assert(hilti::statement::assert::Exception(), std::move($2), {}, {}, __loc__); }
              | ASSERT_EXCEPTION expr ':' expr ';'
                                                 { $$ = hilti::statement::Assert(hilti::statement::assert::Exception(), std::move($2), {}, std::move($4), __loc__); }

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

try_catches   : try_catches try_catch            { $$ = std::move($1); $$.push_back(std::move($2)); }
              | try_catch                        { $$ = std::vector<hilti::statement::try_::Catch>({ std::move($1) }); }

try_catch     : CATCH '(' type local_id ')' block
                                                 { $$ = hilti::statement::try_::Catch(declaration::Parameter($4, $3, declaration::parameter::Kind::In, {}, __loc__), std::move($6), __loc__); }
              | CATCH block                      { $$ = hilti::statement::try_::Catch(std::move($2), __loc__); }

stmt_decl     : local_decl                       { $$ = hilti::statement::Declaration($1, __loc__); }
              | type_decl                        { $$ = hilti::statement::Declaration($1, __loc__); }
              | constant_decl                    { $$ = hilti::statement::Declaration($1, __loc__); }
              ;

stmt_expr     : expr                             { $$ = hilti::statement::Expression($1, __loc__); }

/* Types */

base_type_no_attrs
              : ANY                              { $$ = hilti::type::Any(__loc__); }
              | ADDRESS                          { $$ = hilti::type::Address(__loc__); }
              | BOOL                             { $$ = hilti::type::Bool(__loc__); }
              | BYTES                            { $$ = hilti::type::Bytes(__loc__); }
              | ERROR                            { $$ = hilti::type::Error(__loc__); }
              | INTERVAL                         { $$ = hilti::type::Interval(__loc__); }
              | NETWORK                          { $$ = hilti::type::Network(__loc__); }
              | PORT                             { $$ = hilti::type::Port(__loc__); }
              | REAL                             { $$ = hilti::type::Real(__loc__); }
              | REGEXP                           { $$ = hilti::type::RegExp(__loc__); }
              | STREAM                           { $$ = hilti::type::Stream(__loc__); }
              | STRING                           { $$ = hilti::type::String(__loc__); }
              | TIME                             { $$ = hilti::type::Time(__loc__); }
              | VOID                             { $$ = hilti::type::Void(__loc__); }

              | INT type_param_begin CUINTEGER type_param_end            { $$ = hilti::type::SignedInteger($3, __loc__); }
              | INT type_param_begin '*' type_param_end                  { $$ = hilti::type::SignedInteger(hilti::type::Wildcard(), __loc__); }
              | UINT type_param_begin CUINTEGER type_param_end           { $$ = hilti::type::UnsignedInteger($3, __loc__); }
              | UINT type_param_begin '*' type_param_end                 { $$ = hilti::type::UnsignedInteger(hilti::type::Wildcard(), __loc__); }

              | OPTIONAL type_param_begin type type_param_end            { $$ = hilti::type::Optional($3, __loc__); }
              | RESULT type_param_begin type type_param_end              { $$ = hilti::type::Result($3, __loc__); }
              | VIEW type_param_begin type type_param_end                { $$ = viewForType(std::move($3), __loc__); }
              | ITERATOR type_param_begin type type_param_end            { $$ = iteratorForType(std::move($3), false, __loc__); }
              | CONST_ITERATOR type_param_begin type type_param_end      { $$ = iteratorForType(std::move($3), true, __loc__); }
              | STRONG_REF type_param_begin type type_param_end          { $$ = hilti::type::StrongReference($3, __loc__); }
              | STRONG_REF type_param_begin '*' type_param_end           { $$ = hilti::type::StrongReference(hilti::type::Wildcard(), __loc__); }
              | VALUE_REF type_param_begin type type_param_end           { $$ = hilti::type::ValueReference($3, __loc__); }
              | VALUE_REF type_param_begin '*' type_param_end            { $$ = hilti::type::ValueReference(hilti::type::Wildcard(), __loc__); }
              | WEAK_REF type_param_begin type type_param_end            { $$ = hilti::type::WeakReference($3, __loc__); }
              | WEAK_REF type_param_begin '*' type_param_end             { $$ = hilti::type::WeakReference(hilti::type::Wildcard(), __loc__); }

              | LIST type_param_begin '*' type_param_end                 { $$ = hilti::type::List(hilti::type::Wildcard(), __loc__); }
              | LIST type_param_begin type type_param_end                { $$ = hilti::type::List(std::move($3), __loc__); }
              | VECTOR type_param_begin '*' type_param_end               { $$ = hilti::type::Vector(hilti::type::Wildcard(), __loc__); }
              | VECTOR type_param_begin type type_param_end              { $$ = hilti::type::Vector(std::move($3), __loc__); }
              | SET type_param_begin '*' type_param_end                  { $$ = hilti::type::Set(hilti::type::Wildcard(), __loc__); }
              | SET type_param_begin type type_param_end                 { $$ = hilti::type::Set(std::move($3), __loc__); }
              | MAP type_param_begin '*' type_param_end                  { $$ = hilti::type::Map(hilti::type::Wildcard(), __loc__); }
              | MAP type_param_begin type ',' type type_param_end        { $$ = hilti::type::Map(std::move($3), std::move($5), __loc__); }

              | EXCEPTION                        { $$ = hilti::type::Exception(__loc__); }
              | EXCEPTION ':' type               { $$ = hilti::type::Exception(std::move($3), __loc__); }

              | LIBRARY_TYPE '(' CSTRING ')'     { $$ = hilti::type::Library(std::move($3), __loc__); }

              | tuple_type                       { $$ = std::move($1); }
              | struct_type                      { $$ = std::move($1); }
              | union_type                       { $$ = std::move($1); }
              | enum_type                        { $$ = std::move($1); }
              ;

base_type     : base_type_no_attrs opt_type_flags
                                                 { $$ = type::addFlags($1, $2); }
              ;

type          : base_type                        { $$ = std::move($1); }
              | function_type                    { $$ = std::move($1); }
              | scoped_id                        { $$ = hilti::type::UnresolvedID(std::move($1)); }
              ;

type_param_begin:
              '<'
              { driver->disableExpressionMode(); }

type_param_end:
              '>'
              { driver->enableExpressionMode(); }

opt_type_flags: /* empty */                      { $$ = hilti::type::Flags(); }
              /*  type_flag opt_type_flags         { $$ = $1 + $2; } -- no type flags currently */

function_type : opt_func_flavor FUNCTION '(' opt_func_params ')' ARROW func_result
                                                 { $$ = hilti::type::Function($7, $4, $1, __loc__); }
              ;

tuple_type    : TUPLE type_param_begin '*' type_param_end                { $$ = hilti::type::Tuple(hilti::type::Wildcard(), __loc__); }
              | TUPLE type_param_begin tuple_type_elems type_param_end   { $$ = hilti::type::Tuple(std::move($3), __loc__); }
              ;

tuple_type_elems
              : tuple_type_elems ',' tuple_type_elem
                                                 { $$ = std::move($1); $$.push_back(std::move($3)); }
              | tuple_type_elem                  { $$ = std::vector<std::pair<hilti::ID, hilti::Type>>{ std::move($1) }; }
              ;

tuple_type_elem
              : type                             { $$ = std::make_pair(hilti::ID(), std::move($1)); }
              | local_id ':' type                { $$ = std::make_pair(std::move($1), std::move($3)); }
              ;

struct_type   : STRUCT opt_struct_params '{' struct_fields '}'     { $$ = hilti::type::Struct(std::move($2), std::move($4), __loc__); }

opt_struct_params
              : '(' opt_func_params ')'          { $$ = std::move($2); }
              | /* empty */                      { $$ = std::vector<hilti::type::function::Parameter>{}; }

struct_fields : struct_fields struct_field       { $$ = std::move($1); $$.push_back($2); }
              | /* empty */                      { $$ = std::vector<hilti::type::struct_::Field>{}; }

struct_field  : type local_id opt_attributes ';' { $$ = hilti::type::struct_::Field(std::move($2), std::move($1), std::move($3), __loc__); }
              | func_flavor opt_func_cc func_result local_id '(' opt_func_params ')' opt_attributes ';' {
                                                   auto ftype = hilti::type::Function(std::move($3), std::move($6), $1, __loc__);
                                                   $$ = hilti::type::struct_::Field(std::move($4), $2, std::move(ftype), $8, __loc__);
                                                   }

union_type    : UNION opt_attributes'{' opt_union_fields '}'
                                                 { $$ = hilti::type::Union(std::move($4), __loc__); }

opt_union_fields : union_fields                  { $$ = $1; }
              | /* empty */                      { $$ = std::vector<hilti::type::union_::Field>(); }

union_fields  : union_fields ',' union_field     { $$ = std::move($1); $$.push_back(std::move($3)); }
              | union_field                      { $$ = std::vector<hilti::type::union_::Field>(); $$.push_back(std::move($1)); }

union_field  : type local_id opt_attributes      { $$ = hilti::type::union_::Field(std::move($2), std::move($1), std::move($3), __loc__); }

enum_type     : ENUM '{' enum_labels '}'         { $$ = hilti::type::Enum(std::move($3), __loc__); }
              | ENUM '<' '*' '>'                 { $$ = hilti::type::Enum(type::Wildcard(), __loc__); }

enum_labels   : enum_labels ',' enum_label       { $$ = std::move($1); $$.push_back(std::move($3)); }
              | enum_label                       { $$ = std::vector<hilti::type::enum_::Label>(); $$.push_back(std::move($1)); }
              ;

enum_label    : local_id                         { $$ = hilti::type::enum_::Label(std::move($1), __loc__); }
              | local_id '=' CUINTEGER           { $$ = hilti::type::enum_::Label(std::move($1), $3, __loc__); }
              ;

/* Expressions */

expr          : expr_0                           { $$ = std::move($1); }
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
              | expr_2 '?' expr_1 ':' expr_1     { $$ = hilti::expression::Ternary(std::move($1), std::move($3), std::move($5), __loc__); }
              | expr_2                           { $$ = std::move($1); }

expr_2        : expr_2 OR expr_3                 { $$ = hilti::expression::LogicalOr(std::move($1), std::move($3), __loc__); }
              | expr_3                           { $$ = std::move($1); }

expr_3        : expr_3 AND expr_4                { $$ = hilti::expression::LogicalAnd(std::move($1), std::move($3), __loc__); }
              | expr_4                           { $$ = std::move($1); }

expr_4        : expr_4 EQ expr_5                 { $$ = hilti::expression::UnresolvedOperator(hilti::operator_::Kind::Equal, {std::move($1), std::move($3)}, __loc__); }
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
              | expr_d MINUSMINUS                { $$ = hilti::expression::UnresolvedOperator(hilti::operator_::Kind::DecrPostfix, {std::move($1)}, __loc__); }
              | expr_d PLUSPLUS                  { $$ = hilti::expression::UnresolvedOperator(hilti::operator_::Kind::IncrPostfix, {std::move($1)}, __loc__); }
              | expr_d TRYATTR member_expr       { $$ = hilti::expression::UnresolvedOperator(hilti::operator_::Kind::TryMember, {std::move($1), std::move($3)}, __loc__); }
              | expr_e                           { $$ = std::move($1); }

expr_e        : BEGIN_ '(' expr ')'              { $$ = hilti::expression::UnresolvedOperator(hilti::operator_::Kind::Begin, {std::move($3)}, __loc__); }
              | CAST type_param_begin type type_param_end '(' expr ')'   { $$ = hilti::expression::UnresolvedOperator(hilti::operator_::Kind::Cast, {std::move($6), hilti::expression::Type_(std::move($3))}, __loc__); }
              | END_ '(' expr ')'                { $$ = hilti::expression::UnresolvedOperator(hilti::operator_::Kind::End, {std::move($3)}, __loc__); }
              | MOVE '(' expr ')'                { $$ = hilti::expression::Move(std::move($3), __loc__); }
              | UNPACK type_param_begin type type_param_end tuple_expr   { $$ = hilti::expression::UnresolvedOperator(hilti::operator_::Kind::Unpack, {hilti::expression::Type_(std::move($3)), std::move($5)}, __loc__); }
              | NEW expr                         { $$ = hilti::expression::UnresolvedOperator(hilti::operator_::Kind::New, {std::move($2), hilti::expression::Ctor(hilti::ctor::Tuple({}, __loc__))}, __loc__); }
              | NEW type                         { $$ = hilti::expression::UnresolvedOperator(hilti::operator_::Kind::New, {hilti::expression::Type_(std::move($2)), hilti::expression::Ctor(hilti::ctor::Tuple({}, __loc__))}, __loc__); }
              | NEW type '(' opt_exprs ')'       { $$ = hilti::expression::UnresolvedOperator(hilti::operator_::Kind::New, {hilti::expression::Type_(std::move($2)), hilti::expression::Ctor(hilti::ctor::Tuple(std::move($4), __loc__))}, __loc__); }
              | expr_f                           { $$ = std::move($1); }

expr_f        : ctor                             { $$ = hilti::expression::Ctor(std::move($1), __loc__); }
              | '-' expr_g                       { $$ = hilti::expression::UnresolvedOperator(hilti::operator_::Kind::SignNeg, {std::move($2)}, __loc__); }
              | '[' expr FOR local_id IN expr ']'
                                                 { $$ = hilti::expression::ListComprehension(std::move($6), std::move($2), std::move($4), {},  __loc__); }
              | '[' expr FOR local_id IN expr IF expr ']'
                                                 { $$ = hilti::expression::ListComprehension(std::move($6), std::move($2), std::move($4), std::move($8),  __loc__); }
              | expr_g

expr_g        : '(' expr ')'                     { $$ = hilti::expression::Grouping(std::move($2)); }
              | scoped_id                        { $$ = hilti::expression::UnresolvedID(std::move($1), __loc__); }


member_expr   : local_id                         { $$ = hilti::expression::Member(std::move($1), __loc__); }
              | ERROR                            { $$ = hilti::expression::Member(ID("error", __loc__), __loc__); } // allow methods of that name even though reserved keyword

/* Constants */

ctor          : CBOOL                            { $$ = hilti::ctor::Bool($1, __loc__); }
              | CBYTES                           { $$ = hilti::ctor::Bytes(std::move($1), __loc__); }
              | CSTRING                          { $$ = hilti::ctor::String($1, __loc__); }
              | const_real                       { $$ = hilti::ctor::Real($1, __loc__); }
              | CUINTEGER                        { $$ = hilti::ctor::UnsignedInteger($1, 64, __loc__); }
              | '+' CUINTEGER                    { $$ = hilti::ctor::SignedInteger($2, 64, __loc__); }
              | '-' CUINTEGER                    { if ( $2 > 0x8000000000000000 ) error(@$, "integer overflow on negation");
                                                   $$ = hilti::ctor::SignedInteger(-$2, 64, __loc__); }
              | CNULL                            { $$ = hilti::ctor::Null(__loc__); }

              | CADDRESS                         { $$ = hilti::ctor::Address(hilti::ctor::Address::Value($1), __loc__); }
              | CADDRESS '/' CUINTEGER           { $$ = hilti::ctor::Network(hilti::ctor::Network::Value($1, $3), __loc__); }
              | CPORT                            { $$ = hilti::ctor::Port(hilti::ctor::Port::Value($1), __loc__); }
              | INTERVAL '(' const_real ')'      { $$ = hilti::ctor::Interval(hilti::ctor::Interval::Value($3), __loc__); }
              | INTERVAL '(' const_sint ')'      { $$ = hilti::ctor::Interval(hilti::ctor::Interval::Value($3), __loc__); }
              | TIME '(' const_real ')'          { $$ = hilti::ctor::Time(hilti::ctor::Time::Value($3), __loc__); }
              | TIME '(' const_uint ')'          { $$ = hilti::ctor::Time(hilti::ctor::Time::Value($3 * 1000000000), __loc__); }
              | STREAM '(' CBYTES ')'            { $$ = hilti::ctor::Stream(std::move($3), __loc__); }

              | ERROR '(' CSTRING ')'            { $$ = hilti::ctor::Error(std::move($3), __loc__); }
              | OPTIONAL '(' expr ')'            { $$ = hilti::ctor::Optional(std::move($3), __loc__); }
              | DEFAULT type_param_begin type type_param_end '(' opt_exprs ')'
                                                 { $$ = hilti::ctor::Default(std::move($3), std::move($6), __loc__); }

              | UINT '<' CUINTEGER '>' '(' CUINTEGER ')'
                                                 { $$ = hilti::ctor::UnsignedInteger($6, $3, __loc__); }
              | INT '<' CUINTEGER '>' '(' CUINTEGER ')'
                                                 { $$ = hilti::ctor::SignedInteger($6, $3, __loc__); }
              | INT '<' CUINTEGER '>' '(' '-' CUINTEGER ')'
                                                 { $$ = hilti::ctor::SignedInteger(-$7, $3, __loc__); }

              | list                             { $$ = std::move($1); }
              | map                              { $$ = std::move($1); }
              | regexp                           { $$ = std::move($1); }
              | set                              { $$ = std::move($1); }
              | struct_                          { $$ = std::move($1); }
              | tuple                            { $$ = std::move($1); }
              ;

const_real    : CUREAL                           { $$ = $1; }
              | '+' CUREAL                       { $$ = $2; }
              | '-' CUREAL                       { $$ = -$2; }

const_sint    : CUINTEGER                        { $$ = $1; }
              | '+' CUINTEGER                    { $$ = $2; }
              | '-' CUINTEGER                    { if ( $2 > 0x8000000000000000 ) error(@$, "integer overflow on negation");
                                                   $$ = -$2;
                                                 }

const_uint    : CUINTEGER                        { $$ = $1; }
              | '+' CUINTEGER                    { $$ = $2; }


tuple         : '(' opt_tuple_elems1 ')'         { $$ = hilti::ctor::Tuple(std::move($2), __loc__); }

opt_tuple_elems1
              : tuple_elem ',' opt_tuple_elems2  { $$ = std::vector<hilti::Expression>{std::move($1)}; $$.insert($$.end(), $3.begin(), $3.end()); }
              | /* empty */                      { $$ = std::vector<hilti::Expression>(); }

opt_tuple_elems2
              : tuple_elem ',' opt_tuple_elems2  { $$ = std::vector<hilti::Expression>{std::move($1)}; $$.insert($$.end(), $3.begin(), $3.end()); }
              | tuple_elem                       { $$ = std::vector<hilti::Expression>{ std::move($1)}; }
              | /* empty */                      { $$ = std::vector<hilti::Expression>(); }


tuple_elem    : expr                             { $$ = std::move($1); }
              ;

tuple_expr    : tuple                            { $$ = hilti::expression::Ctor(std::move($1), __loc__); }

list          : '[' opt_exprs ']'                { $$ = hilti::ctor::List(std::move($2), __loc__); }
              | LIST '(' opt_exprs ')'           { $$ = hilti::ctor::List(std::move($3), __loc__); }
              | LIST type_param_begin type type_param_end '(' opt_tuple_elems1 ')'
                                                 { $$ = hilti::ctor::List(std::move($3), std::move($6), __loc__); }
              | VECTOR '(' opt_exprs ')'         { $$ = hilti::ctor::Vector(std::move($3), __loc__); }
              | VECTOR type_param_begin type type_param_end '(' opt_tuple_elems1 ')'
                                                 { $$ = hilti::ctor::Vector(std::move($3), std::move($6), __loc__); }

set           : SET '(' opt_exprs ')'            { $$ = hilti::ctor::Set(std::move($3), __loc__); }
              | SET type_param_begin type type_param_end '(' opt_tuple_elems1 ')'
                                                 { $$ = hilti::ctor::Set(std::move($3), std::move($6), __loc__); }

map           : MAP '(' opt_map_elems ')'        { $$ = hilti::ctor::Map(std::move($3), __loc__); }
              | MAP type_param_begin type ',' type type_param_end '(' opt_map_elems ')'
                                                 { $$ = hilti::ctor::Map(std::move($3), std::move($5), std::move($8), __loc__); }

struct_       : '[' struct_elems ']'         { $$ = hilti::ctor::Struct(std::move($2), __loc__); }

struct_elems  : struct_elems ',' struct_elem     { $$ = std::move($1); $$.push_back($3); }
              | struct_elem                      { $$ = std::vector<hilti::ctor::struct_::Field>{ std::move($1) }; }

struct_elem   : '$' local_id  '=' expr           { $$ = hilti::ctor::struct_::Field(std::move($2), std::move($4)); }

regexp        : re_patterns opt_attributes       { $$ = hilti::ctor::RegExp(std::move($1), std::move($2), __loc__); }

re_patterns   : re_patterns '|' re_pattern_constant
                                                 { $$ = $1; $$.push_back(std::move($3)); }
              | re_pattern_constant              { $$ = std::vector<std::string>{std::move($1)}; }

re_pattern_constant
              : '/' { driver->enablePatternMode(); } CREGEXP { driver->disablePatternMode(); } '/'
                                                 { $$ = std::move($3); }

opt_map_elems : map_elems                        { $$ = std::move($1); }
              | /* empty */                      { $$ = std::vector<hilti::ctor::Map::Element>(); }

map_elems     : map_elems ',' map_elem           { $$ = std::move($1); $$.push_back(std::move($3)); }
              | map_elem                         { $$ = std::vector<hilti::ctor::Map::Element>(); $$.push_back(std::move($1)); }

map_elem      : expr ':' expr                    { $$ = std::make_pair($1, $3); }


attribute     : ATTRIBUTE                       { $$ = hilti::Attribute(std::move($1), __loc__); }
              | ATTRIBUTE '=' expr              { $$ = hilti::Attribute(std::move($1), std::move($3), __loc__); }

opt_attributes
              : opt_attributes attribute        { $$ = hilti::AttributeSet::add($1, $2); }
              | /* empty */                     { $$ = {}; }

%%

void hilti::detail::parser::Parser::error(const Parser::location_type& l, const std::string& m) {
    driver->error(m, toMeta(l));
}
