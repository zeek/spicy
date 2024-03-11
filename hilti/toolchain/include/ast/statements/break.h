// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/statement.h>

namespace hilti::statement {

/** AST node for a `break` statement. */
class Break : public Statement {
public:
    static auto create(ASTContext* ctx, Meta meta = {}) { return ctx->make<Break>(ctx, {}, std::move(meta)); }

protected:
    Break(ASTContext* ctx, Nodes children, Meta meta)
        : Statement(ctx, NodeTags, std::move(children), std::move(meta)) {}

    HILTI_NODE_1(statement::Break, Statement, final);
};

} // namespace hilti::statement
