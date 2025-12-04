// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/declarations/local-variable.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/type.h>

namespace hilti::expression {

/**
 * AST node for grouping another expression inside parentheses. Optionally, the
 * grouping may declare a local variable as well that will be valid for usage
 * inside the grouping's contained expression.
 */
class Grouping : public Expression {
public:
    auto expression() const { return child<Expression>(0); }
    auto local() const { return child<declaration::LocalVariable>(1); }

    QualifiedType* type() const final { return expression()->type(); }

    void setExpression(ASTContext* ctx, Expression* expr) { setChild(ctx, 0, expr); }

    static auto create(ASTContext* ctx, Expression* expr, Meta meta = {}) {
        return ctx->make<Grouping>(ctx, {expr, nullptr}, std::move(meta));
    }

    static auto create(ASTContext* ctx, declaration::LocalVariable* local, Expression* expr, Meta meta = {}) {
        return ctx->make<Grouping>(ctx, {expr, local}, std::move(meta));
    }

protected:
    Grouping(ASTContext* ctx, Nodes children, Meta meta)
        : Expression(ctx, NodeTags, std::move(children), std::move(meta)) {}

    HILTI_NODE_1(expression::Grouping, Expression, final);
};

} // namespace hilti::expression
