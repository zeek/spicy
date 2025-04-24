// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/declarations/local-variable.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/statement.h>

namespace hilti::statement {

/** AST node for a `for` statement. */
class For : public Statement {
public:
    auto local() const { return child<hilti::declaration::LocalVariable>(0); }
    auto sequence() const { return child<::hilti::Expression>(1); }
    auto body() const { return child<hilti::Statement>(2); }

    static auto create(ASTContext* ctx, const hilti::ID& id, hilti::Expression* seq, Statement* body, Meta meta = {}) {
        auto* local = declaration::LocalVariable::create(ctx, id, meta);
        return ctx->make<For>(ctx, {local, seq, body}, std::move(meta));
    }

protected:
    For(ASTContext* ctx, Nodes children, Meta meta) : Statement(ctx, NodeTags, std::move(children), std::move(meta)) {}

    HILTI_NODE_1(statement::For, Statement, final);
};

} // namespace hilti::statement
