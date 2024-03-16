// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/expression.h>
#include <hilti/ast/statement.h>

namespace hilti::statement {

/** AST node for an expression statement. */
class Expression : public Statement {
public:
    auto expression() const { return child<hilti::Expression>(0); }

    static auto create(ASTContext* ctx, hilti::Expression* e, Meta meta = {}) {
        return ctx->make<Expression>(ctx, {e}, std::move(meta));
    }

protected:
    Expression(ASTContext* ctx, Nodes children, Meta meta)
        : Statement(ctx, NodeTags, std::move(children), std::move(meta)) {}

    HILTI_NODE_1(statement::Expression, Statement, final);
};

} // namespace hilti::statement
