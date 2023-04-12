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

namespace hilti {

namespace logging::debug {
inline const DebugStream Parser("parser");
} // namespace logging::debug

namespace detail::parser {

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

} // namespace detail::parser
} // namespace hilti
