// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.
//
// This borrows from https://idlebox.net/2007/flex-bison-cpp-example.

#pragma once

#include <string>

#include <spicy/compiler/detail/parser/driver.h>

/** We compile with a source property to find this. */
#include <__parser.h>

namespace spicy::detail::parser {

/** HILTI's Flex scanner. */
class Scanner : public SpicyFlexLexer {
public:
    Scanner(std::istream* yyin = nullptr, std::ostream* yyout = nullptr) : SpicyFlexLexer(yyin, yyout) {}

    spicy::detail::parser::Parser::token_type lex(spicy::detail::parser::Parser::semantic_type* yylval,
                                                  spicy::detail::parser::location* yylloc,
                                                  spicy::detail::parser::Driver* driver);

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
    void setIgnoreMode(bool enable);
};

} // namespace spicy::detail::parser
