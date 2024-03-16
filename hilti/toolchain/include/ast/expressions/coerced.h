// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/expression.h>
#include <hilti/ast/type.h>

namespace hilti::expression {

/** AST node for an expression that's being coerced from one type to another. */
class Coerced : public Expression {
public:
    auto expression() const { return child<Expression>(0); }

    QualifiedType* type() const final { return child<QualifiedType>(1); }

    static auto create(ASTContext* ctx, Expression* expr, QualifiedType* target, Meta meta = {}) {
        return ctx->make<Coerced>(ctx, {expr, target}, std::move(meta));
    }

protected:
    Coerced(ASTContext* ctx, Nodes children, Meta meta)
        : Expression(ctx, NodeTags, std::move(children), std::move(meta)) {}

    HILTI_NODE_1(expression::Coerced, Expression, final);
};

} // namespace hilti::expression
