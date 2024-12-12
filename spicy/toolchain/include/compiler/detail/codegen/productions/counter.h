// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <spicy/ast/builder/builder.h>
#include <spicy/ast/types/unit.h>
#include <spicy/compiler/detail/codegen/production.h>
#include <spicy/compiler/detail/codegen/productions/visitor.h>

namespace spicy::detail::codegen::production {

/**
 * A production executing a certain number of times as given by an integer
 * expression.
 */
class Counter : public Production {
public:
    Counter(ASTContext* /* ctx */, const std::string& symbol, Expression* e, std::unique_ptr<Production> body,
            const Location& l = location::None)
        : Production(symbol, l), _expression(e), _body(std::move(body)) {}

    auto body() const { return _body.get(); }

    bool isAtomic() const final { return false; };
    bool isEodOk() const final { return isNullable(); };
    bool isLiteral() const final { return false; };
    bool isNullable() const final { return production::isNullable(rhss()); };
    bool isTerminal() const final { return false; };
    Expression* expression() const final { return _expression; }

    std::vector<std::vector<Production*>> rhss() const final { return {{_body.get()}}; };

    Expression* _bytesConsumed(ASTContext* context) const final {
        auto* size = _body->bytesConsumed(context);
        if ( ! size )
            return nullptr;

        return hilti::expression::UnresolvedOperator::create(context, hilti::operator_::Kind::Multiple,
                                                             {_expression, size});
    }

    std::string dump() const override { return hilti::util::fmt("counter(%s): %s", *_expression, _body->symbol()); }

    SPICY_PRODUCTION

private:
    Expression* _expression = nullptr;
    std::unique_ptr<Production> _body;
};

} // namespace spicy::detail::codegen::production
