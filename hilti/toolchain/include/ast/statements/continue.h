// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/forward.h>
#include <hilti/ast/statement.h>

namespace hilti::statement {

/** AST node for a `continue` statement. */
class Continue : public Statement {
public:
    static auto create(ASTContext* ctx, Meta meta = {}) {
        return std::shared_ptr<Continue>(new Continue(ctx, {}, std::move(meta)));
    }

protected:
    Continue(ASTContext* ctx, Nodes children, Meta meta)
        : Statement(ctx, NodeTags, std::move(children), std::move(meta)) {}

    HILTI_NODE_1(statement::Continue, Statement, final);
};

} // namespace hilti::statement
