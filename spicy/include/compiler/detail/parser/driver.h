// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#ifdef yylex
#undef yylex
// Work-around for bison messing up the function name by adding the local namespace.
#define yylex lex
#endif

#include <memory.h>

#include <iostream>
#include <string>

#include <hilti/ast/all.h>
#include <spicy/ast/all.h>

#undef YY_DECL
#define YY_DECL                                                                                                        \
    spicy::detail::parser::Parser::token_type                                                                          \
    spicy::detail::parser::Scanner::lex(spicy::detail::parser::Parser::semantic_type* yylval,                          \
                                        spicy::detail::parser::location* yylloc,                                       \
                                        spicy::detail::parser::Driver* driver)

#define YYSTYPE yystype_spicy

#ifndef __FLEX_LEXER_H
#define yyFlexLexer SpicyFlexLexer
#include <FlexLexer.h>

#undef yyFlexLexer
#endif

/** Bison value type. */
struct yystype_spicy {
    bool bool_ = false;
    double real = 0.0;
    uint64_t uint = 0;
    int64_t sint = 0;
    std::string str;

    hilti::ID id;
    hilti::Declaration declaration;
    hilti::Type type;
    hilti::Ctor ctor;
    hilti::Expression expression;
    hilti::Statement statement;
    hilti::Attribute attribute;
    hilti::Function function;

    std::optional<hilti::Expression> opt_expression;
    std::optional<hilti::Statement> opt_statement;
    std::optional<hilti::AttributeSet> opt_attributes;

    hilti::declaration::Linkage linkage;
    hilti::declaration::parameter::Kind function_parameter_kind;
    hilti::function::CallingConvention function_calling_convention;
    hilti::type::function::Parameter function_parameter;
    hilti::type::function::Result function_result;
    hilti::type::function::Flavor function_flavor;
    hilti::statement::switch_::Case switch_case;

    std::vector<std::string> strings;
    std::vector<hilti::Declaration> declarations;
    std::vector<hilti::Expression> expressions;
    std::vector<hilti::Statement> statements;
    std::vector<hilti::type::function::Parameter> function_parameters;
    std::vector<hilti::statement::switch_::Case> switch_cases;

    std::pair<hilti::ID, hilti::Type> tuple_type_elem;
    std::vector<std::pair<hilti::ID, hilti::Type>> tuple_type_elems;

    hilti::type::struct_::Field struct_field;
    hilti::ctor::struct_::Field struct_elem;
    std::vector<hilti::type::struct_::Field> struct_fields;
    std::vector<hilti::ctor::struct_::Field> struct_elems;

    hilti::ctor::Map::Element map_elem;
    std::vector<hilti::ctor::Map::Element> map_elems;

    hilti::type::enum_::Label enum_label;
    std::vector<hilti::type::enum_::Label> enum_labels;

    spicy::type::bitfield::Bits bitfield_bits_spec;
    std::vector<spicy::type::bitfield::Bits> bitfield_bits;

    std::pair<std::vector<hilti::Declaration>, std::vector<hilti::Statement>> decls_and_stmts;

    // Spicy-only
    std::optional<hilti::ID> opt_id;
    std::vector<spicy::type::unit::Item> unit_items;
    spicy::type::unit::Item unit_item;
    spicy::Engine engine;
    std::vector<spicy::Hook> hooks;
    spicy::Hook hook;

    spicy::type::unit::item::switch_::Case unit_switch_case;
    std::vector<spicy::type::unit::item::switch_::Case> unit_switch_cases;
};

namespace spicy {

namespace logging::debug {
inline const hilti::logging::DebugStream Parser("parser");
} // namespace logging::debug

namespace detail {
namespace parser {

class Parser;
class Scanner;

/** Driver for flex/bison. */
class Driver {
public:
    hilti::Result<hilti::Node> parse(std::istream& in, const std::string& filename);
    hilti::Result<hilti::Node> parseExpression(const std::string& expression, const Meta& m = Meta());

    Scanner* scanner() const { return _scanner; }
    Parser* parser() const { return _parser; }

    // Methods for the parser.

    std::string* currentFile() { return &_filename; }
    int currentLine() { return _line; }
    void error(const std::string& msg, const Meta& m);
    void enablePatternMode();
    void disablePatternMode();
    void enableExpressionMode();
    void disableExpressionMode();
    void enableDottedIDMode();
    void disableDottedIDMode();
    void enableHookIDMode();
    void disableHookIDMode();
    void setDestinationModule(Module m) { _module = std::move(m); }
    void setDestinationExpression(Expression e) { _expression = std::move(e); }
    int nextToken();

private:
    Module _module;
    Expression _expression;
    std::string _filename;
    int _line{};
    Parser* _parser = nullptr;
    Scanner* _scanner = nullptr;
    int _expression_mode = 0;
    int _next_token = 0;
};

} // namespace parser
} // namespace detail
} // namespace spicy
