// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <utility>
#include <vector>

#include <spicy/ast/types/unit.h>
#include <spicy/compiler/detail/codegen/production.h>

namespace spicy::detail::codegen::production {

/**
 * Production that decides between alternatives based on which value out of a
 * set of options a given expression matches; plus an optional default if none matches.
 */
class Switch : public ProductionBase, public spicy::trait::isNonTerminal {
public:
    using Cases = std::vector<std::pair<std::vector<Expression>, Production>>;

    Switch(const std::string& symbol, Expression expr, Cases cases, std::optional<Production> default_,
           AttributeSet attributes, const Location& l = location::None)
        : ProductionBase(symbol, l),
          _expression(std::move(expr)),
          _cases(std::move(cases)),
          _default(std::move(default_)),
          _attributes(std::move(attributes)) {}

    const Expression& expression() const { return _expression; }
    const Cases& cases() const { return _cases; }
    const std::optional<Production>& default_() const { return _default; }
    const AttributeSet& attributes() const { return _attributes; }

    // Production API
    std::vector<std::vector<Production>> rhss() const;
    std::optional<spicy::Type> type() const { return {}; }
    bool nullable() const { return production::nullable(rhss()); }
    bool eodOk() const {
        // Always false. If one of the branches is ok with no data, it will
        // indicate so itself.
        return false;
    }
    bool atomic() const { return false; }
    std::string render() const;

private:
    Expression _expression;
    Cases _cases;
    std::optional<Production> _default;
    AttributeSet _attributes;
};

} // namespace spicy::detail::codegen::production
