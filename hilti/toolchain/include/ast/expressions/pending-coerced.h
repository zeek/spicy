// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

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

    QualifiedType* type() const final { return child<QualifiedType>(1); }

    static auto create(ASTContext* ctx, Expression* expr, QualifiedType* type, Meta meta = {}) {
        return ctx->make<PendingCoerced>(ctx, {expr, type}, std::move(meta));
    }

protected:
    PendingCoerced(ASTContext* ctx, Nodes children, Meta meta)
        : Expression(ctx, NodeTags, std::move(children), std::move(meta)) {}

    HILTI_NODE_1(expression::PendingCoerced, Expression, final);
};

} // namespace hilti::expression
