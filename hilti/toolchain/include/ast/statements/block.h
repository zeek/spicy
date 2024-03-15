// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/statement.h>

namespace hilti::statement {

/** AST node for a block statement. */
class Block : public Statement {
public:
    auto statements() const { return childrenOfType<Statement>(); }

    void add(ASTContext* ctx, Statement* s) { addChild(ctx, s); }

    /** Internal method for use by builder API only. */
    void _add(ASTContext* ctx, Statement* s) { addChild(ctx, s); }

    /** Internal method for use by builder API only. */
    auto _lastStatement() { return children().back()->as<Statement>(); }

    static auto create(ASTContext* ctx, Statements stmts, Meta meta = {}) {
        return ctx->make<Block>(ctx, std::move(stmts), std::move(meta));
    }

    static auto create(ASTContext* ctx, const Meta& meta = {}) { return create(ctx, {}, meta); }

protected:
    Block(ASTContext* ctx, Nodes children, Meta meta)
        : Statement(ctx, NodeTags, std::move(children), std::move(meta)) {}

    HILTI_NODE_1(statement::Block, Statement, final);
};

} // namespace hilti::statement
