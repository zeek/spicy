// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <iostream>
#include <utility>

#include <hilti/base/logger.h>
#include <hilti/base/timing.h>
#include <hilti/compiler/detail/parser/driver.h>
#include <hilti/compiler/detail/parser/scanner.h>
#include <hilti/compiler/plugin.h>

/** We compile with a source property to find this. */
#include <__parser.h>

using namespace hilti;
using namespace hilti::detail::parser;

Result<declaration::Module*> detail::parser::parseSource(Builder* builder, std::istream& in,
                                                         const std::string& filename) {
    util::timing::Collector _("hilti/compiler/ast/parser");

    return Driver().parse(builder, in, filename);
}

Result<declaration::Module*> detail::parser::Driver::parse(Builder* builder, std::istream& in,
                                                           const std::string& filename) {
    _builder = builder;

    auto old_errors = logger().errors();
    _filename = filename;

    Scanner scanner(&in);
    _scanner = &scanner;

    Parser parser(this, _builder);
    _parser = &parser;

    hilti::logging::Stream dbg_stream_parser(hilti::logging::debug::Parser);

    if ( logger().isEnabled(logging::debug::Parser) ) {
        _parser->set_debug_stream(dbg_stream_parser);
        _parser->set_debug_level(1);
    }

    _expression_mode = 1;
    _scanner->enableExpressionMode();
    _parser->parse();

    _builder = nullptr;

    if ( logger().errors() > old_errors )
        return result::Error("parse error");

    return {std::move(_module)};
}

void detail::parser::Driver::error(const std::string& msg, const Meta& m) { logger().error(msg, m.location()); }

void detail::parser::Driver::disablePatternMode() { _scanner->disablePatternMode(); }

void detail::parser::Driver::enablePatternMode() { _scanner->enablePatternMode(); }

void detail::parser::Driver::disableExpressionMode() {
    if ( --_expression_mode == 0 )
        _scanner->disableExpressionMode();
}

void detail::parser::Driver::enableExpressionMode() {
    if ( _expression_mode++ == 0 )
        _scanner->enableExpressionMode();
}

void detail::parser::Driver::disableDottedIDMode() { _scanner->disableDottedIDMode(); }

void detail::parser::Driver::enableDottedIDMode() { _scanner->enableDottedIDMode(); }
