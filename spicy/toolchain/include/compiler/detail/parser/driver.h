// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#ifdef yylex
#undef yylex
// Work-around for bison messing up the function name by adding the local namespace.
#define yylex lex
#endif

#include <memory.h>

#include <iostream>
#include <string>
#include <utility>
#include <vector>

#include <hilti/ast/all.h>
#include <hilti/base/preprocessor.h>

#include <spicy/ast/all.h>
#include <spicy/autogen/config.h>

#undef YY_DECL
#define YY_DECL                                                                                                        \
    spicy::detail::parser::Parser::token_type                                                                          \
    spicy::detail::parser::Scanner::lex(spicy::detail::parser::Parser::semantic_type* yylval,                          \
                                        spicy::detail::parser::location* yylloc,                                       \
                                        spicy::detail::parser::Driver* driver)

#ifndef __FLEX_LEXER_H
#define yyFlexLexer SpicyFlexLexer
#include <FlexLexer.h>

#undef yyFlexLexer
#endif

namespace spicy {

namespace logging::debug {
inline const hilti::logging::DebugStream Parser("parser");
} // namespace logging::debug

namespace detail::parser {

class Parser;
class Scanner;

/** Driver for flex/bison. */
class Driver {
public:
    Driver() : _preprocessor(spicy::configuration().preprocessor_constants) {}

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
    void enableNewKeywordMode();
    void disableNewKeywordMode();
    void setDestinationModule(Module m) { _module = std::move(m); }
    void setDestinationExpression(Expression e) { _expression = std::move(e); }
    int nextToken();
    void processPreprocessorLine(const std::string_view& directive, const std::string_view& expression, const Meta& m);

    void docSummary(const std::string& s);
    void docText(const std::string& s);
    void docField(const std::string& s);
    const DocString& docGet() const;
    DocString&& docGetAndClear();
    void docClear();

private:
    DocString _doc;
    Module _module;
    Expression _expression;
    std::string _filename;
    int _line{};
    Parser* _parser = nullptr;
    Scanner* _scanner = nullptr;
    int _next_token = 0;
    hilti::util::SourceCodePreprocessor _preprocessor;
};

} // namespace detail::parser
} // namespace spicy
