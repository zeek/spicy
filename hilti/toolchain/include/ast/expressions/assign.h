// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/expression.h>
#include <hilti/ast/type.h>

namespace hilti::expression {

/** AST node for a assignment expression. */
class Assign : public Expression {
public:
    auto target() const { return child<Expression>(0); }
    auto source() const { return child<Expression>(1); }

    QualifiedTypePtr type() const final { return target()->type(); }

    void setSource(ASTContext* ctx, const ExpressionPtr& src) { setChild(ctx, 1, src); }

    static auto create(ASTContext* ctx, const ExpressionPtr& target, const ExpressionPtr& src, const Meta& meta = {}) {
        return std::shared_ptr<Assign>(new Assign(ctx, {target, src}, meta));
    }

protected:
    Assign(ASTContext* ctx, Nodes children, Meta meta) : Expression(ctx, std::move(children), std::move(meta)) {}

    HILTI_NODE(hilti, Assign)
};

} // namespace hilti::expression
