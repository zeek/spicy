// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <utility>
#include <vector>

#include <spicy/ast/types/unit.h>
#include <spicy/compiler/detail/codegen/production.h>

namespace spicy::detail::codegen::production {

/**
 * A pair of alternatives between which we decide based on a boolean
 * expression.
 */
class Boolean : public ProductionBase, public spicy::trait::isNonTerminal {
public:
    Boolean(const std::string& symbol, Expression e, Production alt1, Production alt2,
            const Location& l = location::None)
        : ProductionBase(symbol, l),
          _expression(std::move(e)),
          _alternatives(std::make_pair(std::move(alt1), std::move(alt2))) {}

    const Expression& expression() const { return _expression; }
    const std::pair<Production, Production>& alternatives() const { return _alternatives; }

    // Production API
    std::vector<std::vector<Production>> rhss() const { return {{_alternatives.first}, {_alternatives.second}}; }
    std::optional<spicy::Type> type() const { return {}; }
    bool nullable() const { return production::nullable(rhss()); }
    bool eodOk() const {
        // Always false. If one of the branches is ok with no data, it will
        // indicate so itself.
        return false;
    }
    bool atomic() const { return false; }
    std::string render() const {
        return hilti::util::fmt("true: %s / false: %s", _alternatives.first.symbol(), _alternatives.second.symbol());
    }

private:
    Expression _expression;
    std::pair<Production, Production> _alternatives;
};

} // namespace spicy::detail::codegen::production
