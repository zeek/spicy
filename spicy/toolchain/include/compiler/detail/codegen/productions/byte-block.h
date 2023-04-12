// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <utility>
#include <vector>

#include <spicy/ast/types/unit.h>
#include <spicy/compiler/detail/codegen/production.h>

namespace spicy::detail::codegen::production {

/**
 * A production that parses a byte block of a given length with another production.
 *
 * TODO: Not currently used/implemented. Do we need this? (Looks like the old
 * prototype also didn't use it.)
 */
class ByteBlock : public ProductionBase, public spicy::trait::isNonTerminal {
public:
    ByteBlock(const std::string& symbol, Expression e, Production body, const Location& l = location::None)
        : ProductionBase(symbol, l), _expression(std::move(e)), _body(std::move(body)) {}

    const Expression& expression() const { return _expression; }
    const Production& body() const { return _body; }

    // Production API
    std::vector<std::vector<Production>> rhss() const { return {{_body}}; }
    std::optional<spicy::Type> type() const { return {}; }
    bool nullable() const { return production::nullable(rhss()); }
    bool eodOk() const { return nullable(); }
    bool atomic() const { return false; }
    std::string render() const { return hilti::util::fmt("byte-block(%s): %s", _expression, _body.symbol()); }

private:
    Expression _expression;
    Production _body;
};

} // namespace spicy::detail::codegen::production
