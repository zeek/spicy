// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

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

#include <hilti/ast/builder/builder.h>
#include <hilti/ast/doc-string.h>
#include <hilti/base/logger.h>
#include <hilti/base/preprocessor.h>
#include <hilti/base/result.h>

#include <spicy/ast/all.h>
#include <spicy/ast/forward.h>
#include <spicy/autogen/config.h>

#undef YY_DECL
#define YY_DECL                                                                                                        \
    spicy::detail::parser::Parser::token_type                                                                          \
    spicy::detail::parser::Scanner::lex(spicy::detail::parser::Parser::semantic_type* yylval,                          \
                                        spicy::detail::parser::location* yylloc,                                       \
                                        spicy::detail::parser::Driver* driver)

#ifndef __FLEX_LEXER_H
// NOLINTNEXTLINE
#define yyFlexLexer SpicyFlexLexer
#include <FlexLexer.h>

#undef yyFlexLexer
#endif

namespace spicy {

namespace logging::debug {
inline const hilti::logging::DebugStream Parser("parser");
} // namespace logging::debug

namespace detail::parser {

/**
 * Parses a Spicy source file into an AST.
 *
 * @param in stream to read from
 * @param filename path associated with the input
 *
 * Returns: The parsed AST, or a corresponding error if parsing failed.
 */
extern hilti::Result<hilti::declaration::Module*> parseSource(Builder* builder, std::istream& in,
                                                              const std::string& filename);

/**
 * Parses a single Spicy expression into a corresponding AST.
 *
 * @param expr expression to parse.
 * @param m optional meta information to associate with expression
 *
 * Returns: The parsed expression, or a corresponding error if parsing failed.
 */
extern hilti::Result<Expression*> parseExpression(Builder* builder, const std::string& expr, const Meta& meta = Meta());

class Parser;
class Scanner;

/** Driver for flex/bison. */
class Driver {
public:
    Driver() : _preprocessor(spicy::configuration().preprocessor_constants) {}

    hilti::Result<hilti::declaration::Module*> parse(Builder* builder, std::istream& in, const std::string& filename);
    hilti::Result<Expression*> parseExpression(Builder* builder, const std::string& expression, const Meta& m = Meta());

    Scanner* scanner() const { return _scanner; }
    Parser* parser() const { return _parser; }
    Builder* builder() const { return _builder; }

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
    void setDestinationModule(hilti::declaration::Module* m) { _module = m; }
    void setDestinationExpression(Expression* e) { _expression = e; }
    int nextToken();
    void processPreprocessorLine(const std::string_view& directive, const std::string_view& expression, const Meta& m);

    void docSummary(const std::string& s);
    void docText(const std::string& s);
    void docField(const std::string& s);
    const hilti::DocString& docGet() const;
    hilti::DocString&& docGetAndClear();
    void docClear();

private:
    Builder* _builder = nullptr;
    hilti::DocString _doc;
    hilti::declaration::Module* _module = nullptr;
    Expression* _expression = nullptr;
    std::string _filename;
    int _line{};
    Parser* _parser = nullptr;
    Scanner* _scanner = nullptr;
    int _next_token = 0;
    hilti::util::SourceCodePreprocessor _preprocessor;
};

} // namespace detail::parser
} // namespace spicy
