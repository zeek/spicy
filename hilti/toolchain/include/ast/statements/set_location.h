// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/expression.h>
#include <hilti/ast/statement.h>

namespace hilti::statement {

class SetLocation : public Statement {
public:
    auto expression() const { return child<::hilti::Expression>(0); }

    static auto create(ASTContext* ctx, hilti::Expression* expr, Meta meta = {}) {
        return ctx->make<SetLocation>(ctx, {expr}, std::move(meta));
    }

protected:
    SetLocation(ASTContext* ctx, Nodes children, Meta meta)
        : Statement(ctx, NodeTags, std::move(children), std::move(meta)) {}

    HILTI_NODE_1(statement::SetLocation, Statement, final);
};

} // namespace hilti::statement
