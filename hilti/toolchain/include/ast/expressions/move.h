// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/expression.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/bool.h>

namespace hilti::expression {

/** AST node for a `move` expression. */
class Move : public Expression {
public:
    auto expression() const { return child<Expression>(0); }

    QualifiedType* type() const final { return expression()->type(); }

    static auto create(ASTContext* ctx, Expression* expression, Meta meta = {}) {
        return ctx->make<Move>(ctx, {expression}, std::move(meta));
    }

protected:
    Move(ASTContext* ctx, Nodes children, Meta meta)
        : Expression(ctx, NodeTags, std::move(children), std::move(meta)) {}

    HILTI_NODE_1(expression::Move, Expression, final);
};

} // namespace hilti::expression
