// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <spicy/ast/types/unit.h>
#include <spicy/compiler/detail/codegen/production.h>
#include <spicy/compiler/detail/codegen/productions/visitor.h>

namespace spicy::detail::codegen::production {

/**
 * Production that decides between alternatives based on which value out of a
 * set of options a given expression matches; plus an optional default if none matches.
 */
class Switch : public Production {
public:
    using Cases = std::vector<std::pair<std::vector<Expression*>, std::unique_ptr<Production>>>;

    Switch(ASTContext* /* ctx */, const std::string& symbol, Expression* expr, Cases cases,
           std::unique_ptr<Production> default_, AttributeSet* attributes, Expression* condition,
           const Location& l = location::None)
        : Production(symbol, l),
          _expression(expr),
          _cases(std::move(cases)),
          _default(std::move(default_)),
          _attributes(attributes),
          _condition(condition) {}

    const auto& condition() const { return _condition; }
    const auto& cases() const { return _cases; }
    const auto* default_() const { return _default.get(); }
    const auto& attributes() const { return _attributes; }

    bool isAtomic() const final { return false; };
    bool isEodOk() const final {
        // Always false. If one of the branches is ok with no data, it will indicate so itself.
        return false;
    }
    bool isLiteral() const final { return false; };
    bool isNullable() const final { return production::isNullable(rhss()); };
    bool isTerminal() const final { return false; };

    Expression* expression() const final { return _expression; }
    std::vector<std::vector<Production*>> rhss() const final;

    std::string dump() const final;

    SPICY_PRODUCTION

private:
    Expression* _expression = nullptr;
    Cases _cases;
    std::unique_ptr<Production> _default;
    AttributeSet* _attributes = nullptr;
    Expression* _condition = nullptr;
};

} // namespace spicy::detail::codegen::production
