// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/expression.h>
#include <hilti/ast/type.h>

namespace hilti::expression {

/** AST node for a ternary expression. */
class Ternary : public Expression {
public:
    auto condition() const { return child<Expression>(0); }
    auto true_() const { return child<Expression>(1); }
    auto false_() const { return child<Expression>(2); }

    QualifiedType* type() const final {
        // TODO(robin): Currently we enforce both having the same type; we
        // might need to coerce to target type though.
        return true_()->type();
    }

    void setTrue(ASTContext* ctx, Expression* e) { setChild(ctx, 1, e); }
    void setFalse(ASTContext* ctx, Expression* e) { setChild(ctx, 2, e); }

    static auto create(ASTContext* ctx, Expression* cond, Expression* true_, Expression* false_, Meta meta = {}) {
        return ctx->make<Ternary>(ctx, {cond, true_, false_}, std::move(meta));
    }

protected:
    Ternary(ASTContext* ctx, Nodes children, Meta meta)
        : Expression(ctx, NodeTags, std::move(children), std::move(meta)) {}

    HILTI_NODE_1(expression::Ternary, Expression, final);
};

} // namespace hilti::expression
