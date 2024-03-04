// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/expression.h>
#include <hilti/ast/type.h>

namespace hilti::expression {

/** AST node for an expression that will be coerced from one type to another.
 *  The actual coercion expression will be generated later and replace the
 *  this node during the apply-coercions phase.
 */
class PendingCoerced : public Expression {
public:
    auto expression() const { return child<Expression>(0); }

    QualifiedTypePtr type() const final { return child<QualifiedType>(1); }

    static auto create(ASTContext* ctx, const ExpressionPtr& expr, const QualifiedTypePtr& type,
                       const Meta& meta = {}) {
        return std::shared_ptr<PendingCoerced>(new PendingCoerced(ctx, {expr, type}, meta));
    }

protected:
    PendingCoerced(ASTContext* ctx, Nodes children, Meta meta)
        : Expression(ctx, std::move(children), std::move(meta)) {}

    HILTI_NODE(hilti, PendingCoerced)
};

} // namespace hilti::expression
