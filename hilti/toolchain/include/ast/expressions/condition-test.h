// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/expression.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/result.h>
#include <hilti/ast/types/void.h>

namespace hilti::expression {

/** AST node for an condition-test expression. */
class ConditionTest : public Expression {
public:
    auto condition() const { return child<Expression>(1); }
    auto error() const { return child<Expression>(2); }

    QualifiedType* type() const final { return child<QualifiedType>(0); }

    void setCondition(ASTContext* ctx, Expression* cond) { setChild(ctx, 1, cond); }
    void setError(ASTContext* ctx, Expression* error) { setChild(ctx, 2, error); }

    static auto create(ASTContext* ctx, Expression* cond, Expression* error, Meta meta = {}) {
        auto* result =
            QualifiedType::create(ctx,
                                  type::Result::create(ctx, QualifiedType::create(ctx, type::Void::create(ctx),
                                                                                  Constness::Const)),
                                  Constness::Const);
        return ctx->make<ConditionTest>(ctx, {result, cond, error}, std::move(meta));
    }

protected:
    ConditionTest(ASTContext* ctx, Nodes children, Meta meta)
        : Expression(ctx, NodeTags, std::move(children), std::move(meta)) {}

    HILTI_NODE_1(expression::ConditionTest, Expression, final);
};

} // namespace hilti::expression
