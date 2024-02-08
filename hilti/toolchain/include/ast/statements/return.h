// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

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

    void setExpression(ASTContext* ctx, const ExpressionPtr& c) { setChild(ctx, 0, c); }

    static auto create(ASTContext* ctx, const ExpressionPtr& expr, Meta meta = {}) {
        return std::shared_ptr<Return>(new Return(ctx, {expr}, std::move(meta)));
    }

    static auto create(ASTContext* ctx, Meta meta = {}) { return create(ctx, nullptr, std::move(meta)); }

protected:
    Return(ASTContext* ctx, Nodes children, Meta meta) : Statement(ctx, std::move(children), std::move(meta)) {}

    HILTI_NODE(hilti, Return)
};

} // namespace hilti::statement
