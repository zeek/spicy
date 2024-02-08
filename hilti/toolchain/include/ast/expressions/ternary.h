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

    QualifiedTypePtr type() const final {
        // TODO(robin): Currently we enforce both having the same type; we
        // might need to coerce to target type though.
        return true_()->type();
    }

    void setTrue(ASTContext* ctx, ExpressionPtr e) { setChild(ctx, 1, std::move(e)); }
    void setFalse(ASTContext* ctx, ExpressionPtr e) { setChild(ctx, 2, std::move(e)); }

    static auto create(ASTContext* ctx, const ExpressionPtr& cond, const ExpressionPtr& true_,
                       const ExpressionPtr& false_, const Meta& meta = {}) {
        return std::shared_ptr<Ternary>(new Ternary(ctx, {cond, true_, false_}, meta));
    }

protected:
    Ternary(ASTContext* ctx, Nodes children, Meta meta) : Expression(ctx, std::move(children), std::move(meta)) {}

    HILTI_NODE(hilti, Ternary)
};

} // namespace hilti::expression
