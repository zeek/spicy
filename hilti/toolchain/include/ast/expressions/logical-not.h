// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/expression.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/bool.h>

namespace hilti::expression {

/** AST node for a logical "not" expression. */
class LogicalNot : public Expression {
public:
    auto expression() const { return child<Expression>(0); }

    QualifiedTypePtr type() const final { return child<QualifiedType>(1); }

    void setExpression(ASTContext* ctx, ExpressionPtr e) { setChild(ctx, 0, std::move(e)); }

    static auto create(ASTContext* ctx, const ExpressionPtr& expression, const Meta& meta = {}) {
        return std::shared_ptr<LogicalNot>(
            new LogicalNot(ctx,
                           {expression, QualifiedType::create(ctx, type::Bool::create(ctx, meta), Constness::Const)},
                           meta));
    }

protected:
    LogicalNot(ASTContext* ctx, Nodes children, Meta meta)
        : Expression(ctx, NodeTags, std::move(children), std::move(meta)) {}

    HILTI_NODE_1(expression::LogicalNot, Expression, final);
};

} // namespace hilti::expression
