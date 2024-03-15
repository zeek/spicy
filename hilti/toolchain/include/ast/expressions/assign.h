// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/expression.h>
#include <hilti/ast/type.h>

namespace hilti::expression {

/** AST node for an assignment expression. */
class Assign : public Expression {
public:
    auto target() const { return child<Expression>(0); }
    auto source() const { return child<Expression>(1); }

    QualifiedType* type() const final { return target()->type(); }

    void setSource(ASTContext* ctx, Expression* src) { setChild(ctx, 1, src); }

    static auto create(ASTContext* ctx, Expression* target, Expression* src, Meta meta = {}) {
        return ctx->make<Assign>(ctx, {target, src}, std::move(meta));
    }

protected:
    Assign(ASTContext* ctx, Nodes children, Meta meta)
        : Expression(ctx, NodeTags, std::move(children), std::move(meta)) {}

    HILTI_NODE_1(expression::Assign, Expression, final);
};

} // namespace hilti::expression
