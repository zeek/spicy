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

    QualifiedTypePtr type() const final { return child<QualifiedType>(1); }

    static auto create(ASTContext* ctx, const ExpressionPtr& expr, const QualifiedTypePtr& target,
                       const Meta& meta = {}) {
        return std::shared_ptr<Coerced>(new Coerced(ctx, {expr, target}, meta));
    }

protected:
    Coerced(ASTContext* ctx, Nodes children, Meta meta) : Expression(ctx, std::move(children), std::move(meta)) {}

    HILTI_NODE(hilti, Coerced)
};

} // namespace hilti::expression
