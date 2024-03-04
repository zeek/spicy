// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/expression.h>
#include <hilti/ast/statement.h>

namespace hilti::statement {

/** AST node for a `throw` statement. */
class Throw : public Statement {
public:
    auto expression() const { return child<::hilti::Expression>(0); }

    static auto create(ASTContext* ctx, const ExpressionPtr& expr, Meta meta = {}) {
        return std::shared_ptr<Throw>(new Throw(ctx, {expr}, std::move(meta)));
    }

    static auto create(ASTContext* ctx, Meta meta = {}) {
        return std::shared_ptr<Throw>(new Throw(ctx, {nullptr}, std::move(meta)));
    }

protected:
    Throw(ASTContext* ctx, Nodes children, Meta meta)
        : Statement(ctx, NodeTags, std::move(children), std::move(meta)) {}

    HILTI_NODE_1(statement::Throw, Statement, final);
};

} // namespace hilti::statement
