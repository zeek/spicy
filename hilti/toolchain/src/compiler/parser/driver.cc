// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <iostream>
#include <utility>

#include <hilti/base/logger.h>
#include <hilti/compiler/detail/parser/driver.h>
#include <hilti/compiler/detail/parser/scanner.h>
#include <hilti/compiler/plugin.h>
#include <hilti/global.h>

/** We compile with a source property to find this. */
#include <__parser.h>

using namespace hilti;
using namespace hilti::detail::parser;

Result<hilti::Node> hilti::parseSource(std::istream& in, const std::string& filename) {
    return Driver().parse(in, filename);
}

Result<hilti::Node> Driver::parse(std::istream& in, const std::string& filename) {
    auto old_errors = logger().errors();
    _filename = filename;

    Scanner scanner(&in);
    _scanner = &scanner;

    Parser parser(this);
    _parser = &parser;

    hilti::logging::Stream dbg_stream_parser(hilti::logging::debug::Parser);

    if ( logger().isEnabled(logging::debug::Parser) ) {
        _parser->set_debug_stream(dbg_stream_parser);
        _parser->set_debug_level(1);
    }

    _expression_mode = 1;
    _scanner->enableExpressionMode();
    _parser->parse();

    if ( logger().errors() > old_errors )
        return result::Error("parse error");

    return {std::move(_module)};
}

void Driver::error(const std::string& msg, const Meta& m) { logger().error(msg, m.location()); }

void Driver::disablePatternMode() { _scanner->disablePatternMode(); }

void Driver::enablePatternMode() { _scanner->enablePatternMode(); }

void Driver::disableExpressionMode() {
    if ( --_expression_mode == 0 )
        _scanner->disableExpressionMode();
}

void Driver::enableExpressionMode() {
    if ( _expression_mode++ == 0 )
        _scanner->enableExpressionMode();
}

void Driver::disableDottedIDMode() { _scanner->disableDottedIDMode(); }

void Driver::enableDottedIDMode() { _scanner->enableDottedIDMode(); }
