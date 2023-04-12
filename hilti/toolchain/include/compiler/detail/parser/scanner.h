// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.
//
// This borrows from https://idlebox.net/2007/flex-bison-cpp-example.

#pragma once

#include <string>

#include <hilti/compiler/detail/parser/driver.h>

/** We compile with a source property to find this. */
#include <__parser.h>

namespace hilti::detail::parser {

/** HILTI's Flex scanner. */
class Scanner : public HiltiFlexLexer {
public:
    Scanner(std::istream* yyin = nullptr, std::ostream* yyout = nullptr) : HiltiFlexLexer(yyin, yyout) {}

    hilti::detail::parser::Parser::token_type lex(hilti::detail::parser::Parser::semantic_type* yylval,
                                                  hilti::detail::parser::location* yylloc,
                                                  hilti::detail::parser::Driver* driver);

    void enablePatternMode();
    void disablePatternMode();
    void enableExpressionMode();
    void disableExpressionMode();
    void enableDottedIDMode();
    void disableDottedIDMode();
};

} // namespace hilti::detail::parser
