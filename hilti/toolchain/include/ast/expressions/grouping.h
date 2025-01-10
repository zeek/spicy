// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/expression.h>
#include <hilti/ast/type.h>

namespace hilti::expression {

/** AST node for grouping another expression inside parentheses. */
class Grouping : public Expression {
public:
    auto expression() const { return child<Expression>(0); }

    QualifiedType* type() const final { return expression()->type(); }

    static auto create(ASTContext* ctx, Expression* expr, Meta meta = {}) {
        return ctx->make<Grouping>(ctx, {expr}, std::move(meta));
    }

protected:
    Grouping(ASTContext* ctx, Nodes children, Meta meta)
        : Expression(ctx, NodeTags, std::move(children), std::move(meta)) {}

    HILTI_NODE_1(expression::Grouping, Expression, final);
};

} // namespace hilti::expression
