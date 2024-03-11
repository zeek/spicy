// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <hilti/ast/expression.h>

#include <spicy/compiler/detail/codegen/production.h>
#include <spicy/compiler/detail/codegen/productions/visitor.h>

namespace spicy::detail::codegen::production {

/**
 * A pair of alternatives between which we decide based on a boolean
 * expression.
 */
class Boolean : public Production {
public:
    Boolean(ASTContext* /* ctx */, const std::string& symbol, Expression* e, std::unique_ptr<Production> alt1,
            std::unique_ptr<Production> alt2, const hilti::Location& l = hilti::location::None)
        : Production(symbol, l), _expression(e), _alternatives(std::make_pair(std::move(alt1), std::move(alt2))) {}

    std::pair<Production*, Production*> alternatives() const {
        return std::make_pair(_alternatives.first.get(), _alternatives.second.get());
    }

    bool isAtomic() const final { return false; };
    bool isEodOk() const final {
        // Always false. If one of the branches is ok with no data, it will
        // indicate so itself.
        return false;
    }
    bool isLiteral() const final { return false; };
    bool isNullable() const final { return production::isNullable(rhss()); };
    bool isTerminal() const final { return false; };

    std::vector<std::vector<Production*>> rhss() const final {
        return {{_alternatives.first.get()}, {_alternatives.second.get()}};
    }

    Expression* expression() const final { return _expression; }

    std::string dump() const final {
        return hilti::util::fmt("true: %s / false: %s", _alternatives.first->symbol(), _alternatives.second->symbol());
    }

    SPICY_PRODUCTION

private:
    Expression* _expression = nullptr;
    std::pair<std::unique_ptr<Production>, std::unique_ptr<Production>> _alternatives;
};

} // namespace spicy::detail::codegen::production
