// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/expression.h>
#include <hilti/ast/statement.h>

namespace hilti::statement {

/** AST node for a `return` statement. */
class Return : public Statement {
public:
    auto expression() const { return child<::hilti::Expression>(0); }

    void setExpression(ASTContext* ctx, hilti::Expression* c) { setChild(ctx, 0, c); }

    static auto create(ASTContext* ctx, hilti::Expression* expr, Meta meta = {}) {
        return ctx->make<Return>(ctx, {expr}, std::move(meta));
    }

    static auto create(ASTContext* ctx, Meta meta = {}) { return create(ctx, nullptr, std::move(meta)); }

protected:
    Return(ASTContext* ctx, Nodes children, Meta meta)
        : Statement(ctx, NodeTags, std::move(children), std::move(meta)) {}

    HILTI_NODE_1(statement::Return, Statement, final);
};

} // namespace hilti::statement
