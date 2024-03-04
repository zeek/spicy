// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/expression.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/bool.h>

namespace hilti::expression {

/** AST node for a logical "and" expression. */
class LogicalAnd : public Expression {
public:
    auto op0() const { return child<Expression>(0); }
    auto op1() const { return child<Expression>(1); }

    QualifiedTypePtr type() const final { return child<QualifiedType>(2); }

    void setOp0(ASTContext* ctx, ExpressionPtr e) { setChild(ctx, 0, std::move(e)); }
    void setOp1(ASTContext* ctx, ExpressionPtr e) { setChild(ctx, 1, std::move(e)); }

    static auto create(ASTContext* ctx, const ExpressionPtr& op0, const ExpressionPtr& op1, const Meta& meta = {}) {
        return std::shared_ptr<LogicalAnd>(
            new LogicalAnd(ctx, {op0, op1, QualifiedType::create(ctx, type::Bool::create(ctx, meta), Constness::Const)},
                           meta));
    }

protected:
    LogicalAnd(ASTContext* ctx, Nodes children, Meta meta)
        : Expression(ctx, NodeTags, std::move(children), std::move(meta)) {}

    HILTI_NODE_1(expression::LogicalAnd, Expression, final);
};

} // namespace hilti::expression
