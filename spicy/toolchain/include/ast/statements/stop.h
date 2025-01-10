// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/statement.h>

#include <spicy/ast/forward.h>

namespace spicy::statement {

/** AST node for a `break` statement. */
class Stop : public Statement {
public:
    static auto create(ASTContext* ctx, Meta meta = {}) { return ctx->make<Stop>(ctx, {}, std::move(meta)); }

protected:
    Stop(ASTContext* ctx, Nodes children, Meta meta) : Statement(ctx, NodeTags, std::move(children), std::move(meta)) {}

    SPICY_NODE_1(statement::Stop, Statement, final);
};

} // namespace spicy::statement
