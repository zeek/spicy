// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <iostream>
#include <utility>

#include <hilti/base/logger.h>
#include <hilti/base/timing.h>

#include <spicy/compiler/detail/parser/driver.h>
#include <spicy/compiler/detail/parser/scanner.h>

/** We compile with a source property to find this. */
#include <__parser.h>

using namespace spicy;
using namespace spicy::detail::parser;

hilti::Result<hilti::declaration::Module*> detail::parser::parseSource(Builder* builder, std::istream& in,
                                                                       const std::string& filename) {
    hilti::util::timing::Collector _("spicy/compiler/ast/parser");

    return Driver().parse(builder, in, filename);
}

hilti::Result<Expression*> detail::parser::parseExpression(Builder* builder, const std::string& expr,
                                                           const Meta& meta) {
    spicy::detail::parser::Driver driver;
    return driver.parseExpression(builder, expr, meta);
}

namespace hilti::logging::debug {
inline const DebugStream Parser("parser");
} // namespace hilti::logging::debug

hilti::Result<hilti::declaration::Module*> Driver::parse(Builder* builder, std::istream& in,
                                                         const std::string& filename) {
    _builder = builder;

    auto old_errors = hilti::logger().errors();
    _filename = filename;
    _line = 1;
    _next_token = Parser::token::START_MODULE;

    Scanner scanner(&in);
    _scanner = &scanner;

    Parser parser(this, _builder);
    _parser = &parser;

    hilti::logging::Stream dbg_stream_parser(hilti::logging::debug::Parser);

    if ( hilti::logger().isEnabled(hilti::logging::debug::Parser) ) {
        _parser->set_debug_stream(dbg_stream_parser);
        _parser->set_debug_level(1);
    }

    _parser->parse();

    _builder = nullptr;

    if ( hilti::logger().errors() > old_errors )
        return hilti::result::Error("parse error");

    return _module;
}

hilti::Result<Expression*> Driver::parseExpression(Builder* builder, const std::string& expression, const Meta& m) {
    _builder = builder;

    auto old_errors = hilti::logger().errors();

    if ( m.location() ) {
        _filename = m.location().file();
        _line = m.location().from();
    }
    else {
        _filename = "<expression>";
        _line = 1;
    }

    _next_token = Parser::token::START_EXPRESSION;

    std::stringstream str;
    str << expression;
    Scanner scanner(&str);
    _scanner = &scanner;

    Parser parser(this, _builder);
    _parser = &parser;

    hilti::logging::Stream dbg_stream_parser(hilti::logging::debug::Parser);

    if ( hilti::logger().isEnabled(hilti::logging::debug::Parser) ) {
        _parser->set_debug_stream(dbg_stream_parser);
        _parser->set_debug_level(1);
    }

    _parser->parse();

    _builder = nullptr;

    if ( hilti::logger().errors() > old_errors )
        return hilti::result::Error("parse error");

    return _expression;
}

int Driver::nextToken() {
    int next = _next_token;
    _next_token = 0;
    return next;
}

void Driver::error(const std::string& msg, const Meta& m) { hilti::logger().error(msg, m.location()); }

void Driver::disablePatternMode() { _scanner->disablePatternMode(); }

void Driver::enablePatternMode() { _scanner->enablePatternMode(); }

void Driver::disableExpressionMode() { _scanner->disableExpressionMode(); }

void Driver::enableExpressionMode() { _scanner->enableExpressionMode(); }

void Driver::disableDottedIDMode() { _scanner->disableDottedIDMode(); }

void Driver::enableDottedIDMode() { _scanner->enableDottedIDMode(); }

void Driver::disableHookIDMode() { _scanner->disableHookIDMode(); }

void Driver::enableNewKeywordMode() { _scanner->enableNewKeywordMode(); }

void Driver::disableNewKeywordMode() { _scanner->disableNewKeywordMode(); }

void Driver::enableHookIDMode() { _scanner->enableHookIDMode(); }

void Driver::processPreprocessorLine(const std::string_view& directive, const std::string_view& expression,
                                     const Meta& m) {
    auto state = _preprocessor.processLine(directive, expression);
    if ( ! state ) {
        error(state.error(), m);
        return;
    }

    switch ( *state ) {
        case hilti::util::SourceCodePreprocessor::State::Include: _scanner->setIgnoreMode(false); break;
        case hilti::util::SourceCodePreprocessor::State::Skip: _scanner->setIgnoreMode(true); break;
    }
}

void Driver::docSummary(const std::string& s) { _doc.addSummary(s); }
void Driver::docText(const std::string& s) { _doc.addText(s); }
void Driver::docField(const std::string& s) {
    // TODO
}

const hilti::DocString& Driver::docGet() const { return _doc; }
hilti::DocString&& Driver::docGetAndClear() { return std::move(_doc); }
void Driver::docClear() { _doc = hilti::DocString(); }
