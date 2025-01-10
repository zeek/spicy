// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/statement.h>

namespace hilti::statement {

/** AST node for a `yield` statement. */
class Yield : public Statement {
public:
    static auto create(ASTContext* ctx, Meta meta = {}) { return ctx->make<Yield>(ctx, {}, std::move(meta)); }

protected:
    Yield(ASTContext* ctx, Nodes children, Meta meta)
        : Statement(ctx, NodeTags, std::move(children), std::move(meta)) {}

    HILTI_NODE_1(statement::Yield, Statement, final);
};

} // namespace hilti::statement
