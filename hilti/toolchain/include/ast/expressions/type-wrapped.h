// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/expression.h>
#include <hilti/ast/type.h>

namespace hilti::expression {

/** AST node for an expression wrapped to have a specific type. */
class TypeWrapped : public Expression {
public:
    auto expression() const { return child<Expression>(0); }

    QualifiedTypePtr type() const final { return child<QualifiedType>(1); }

    static auto create(ASTContext* ctx, const ExpressionPtr& expr, const QualifiedTypePtr& type,
                       const Meta& meta = {}) {
        return std::shared_ptr<TypeWrapped>(new TypeWrapped(ctx, {expr, type}, meta));
    }

protected:
    TypeWrapped(ASTContext* ctx, Nodes children, Meta meta)
        : Expression(ctx, NodeTags, std::move(children), std::move(meta)) {}

    HILTI_NODE_1(expression::TypeWrapped, Expression, final);
};

} // namespace hilti::expression
