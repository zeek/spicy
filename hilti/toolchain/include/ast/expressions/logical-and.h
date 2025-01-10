// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

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

    QualifiedType* type() const final { return child<QualifiedType>(2); }

    void setOp0(ASTContext* ctx, Expression* e) { setChild(ctx, 0, e); }
    void setOp1(ASTContext* ctx, Expression* e) { setChild(ctx, 1, e); }

    static auto create(ASTContext* ctx, Expression* op0, Expression* op1, const Meta& meta = {}) {
        return ctx->make<LogicalAnd>(ctx,
                                     {op0, op1,
                                      QualifiedType::create(ctx, type::Bool::create(ctx, meta), Constness::Const)},
                                     meta);
    }

protected:
    LogicalAnd(ASTContext* ctx, Nodes children, Meta meta)
        : Expression(ctx, NodeTags, std::move(children), std::move(meta)) {}

    HILTI_NODE_1(expression::LogicalAnd, Expression, final);
};

} // namespace hilti::expression
