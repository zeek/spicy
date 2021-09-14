// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>
#include <vector>
#ifdef yylex
#undef yylex
// Work-around for bison messing up the function name by adding the local namespace.
#define yylex lex
#endif

#include <memory.h>

#include <iostream>
#include <string>

#include <hilti/ast/all.h>
#include <hilti/base/result.h>

#undef YY_DECL
#define YY_DECL                                                                                                        \
    hilti::detail::parser::Parser::token_type                                                                          \
    hilti::detail::parser::Scanner::lex(hilti::detail::parser::Parser::semantic_type* yylval,                          \
                                        hilti::detail::parser::location* yylloc,                                       \
                                        hilti::detail::parser::Driver* driver)

#ifndef __FLEX_LEXER_H
#define yyFlexLexer HiltiFlexLexer
#include <FlexLexer.h>

#undef yyFlexLexer
#endif

/** Bison value type. */
struct yystype_hilti {
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
    hilti::type::Flags type_flags;

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
    hilti::statement::try_::Catch try_catch;

    std::vector<std::string> strings;
    std::vector<hilti::Declaration> declarations;
    std::vector<hilti::Expression> expressions;
    std::vector<hilti::Statement> statements;
    std::vector<hilti::type::function::Parameter> function_parameters;
    std::vector<hilti::statement::switch_::Case> switch_cases;
    std::vector<hilti::statement::try_::Catch> try_catches;

    std::pair<hilti::ID, hilti::Type> tuple_type_elem;
    std::vector<std::pair<hilti::ID, hilti::Type>> tuple_type_elems;

    hilti::type::struct_::Field struct_field;
    hilti::ctor::struct_::Field struct_elem;
    std::vector<hilti::type::struct_::Field> struct_fields;
    std::vector<hilti::ctor::struct_::Field> struct_elems;

    hilti::type::union_::Field union_field;
    std::vector<hilti::type::union_::Field> union_fields;

    hilti::ctor::Map::Element map_elem;
    std::vector<hilti::ctor::Map::Element> map_elems;

    hilti::type::enum_::Label enum_label;
    std::vector<hilti::type::enum_::Label> enum_labels;

    std::pair<std::vector<hilti::Declaration>, std::vector<hilti::Statement>> decls_and_stmts;
};

namespace hilti {

namespace logging::debug {
inline const DebugStream Parser("parser");
} // namespace logging::debug

namespace detail {
namespace parser {

class Parser;
class Scanner;

/** Driver for flex/bison. */
class Driver {
public:
    Result<hilti::Node> parse(std::istream& in, const std::string& filename);

    Scanner* scanner() const { return _scanner; }
    Parser* parser() const { return _parser; }

    // Methods for the parser.

    std::string* currentFile() { return &_filename; }
    void error(const std::string& msg, const Meta& m);
    void enablePatternMode();
    void disablePatternMode();
    void enableExpressionMode();
    void disableExpressionMode();
    void enableDottedIDMode();
    void disableDottedIDMode();
    void setDestinationModule(Module&& m) { _module = std::move(m); }

private:
    Module _module;
    std::string _filename;
    Parser* _parser = nullptr;
    Scanner* _scanner = nullptr;
    int _expression_mode = 0;
};

} // namespace parser
} // namespace detail
} // namespace hilti
