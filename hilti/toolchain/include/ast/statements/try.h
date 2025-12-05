// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <utility>
#include <vector>

#include <hilti/ast/declarations/parameter.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/statement.h>
#include <hilti/ast/statements/block.h>
#include <hilti/base/logger.h>

namespace hilti::statement {

namespace try_ {

/** AST node for a `catch` block. */
class Catch final : public Node {
public:
    auto parameter() const { return child<declaration::Parameter>(0); }
    auto body() const { return child<hilti::Statement>(1); }

    static auto create(ASTContext* ctx, hilti::Declaration* param, Statement* body, Meta meta = {}) {
        return ctx->make<Catch>(ctx, {param, body}, std::move(meta));
    }

    static auto create(ASTContext* ctx, Statement* body, Meta meta = {}) {
        return ctx->make<Catch>(ctx, {nullptr, body}, std::move(meta));
    }

protected:
    Catch(ASTContext* ctx, Nodes children, Meta meta = {}) : Node(ctx, NodeTags, std::move(children), std::move(meta)) {
        if ( child(0) && ! child(0)->isA<declaration::Parameter>() )
            logger().internalError("'catch' first child must be parameter");
    }

    std::string _dump() const final;

    HILTI_NODE_0(statement::try_::Catch, final);
};

using Catches = NodeVector<Catch>;

} // namespace try_

/** AST node for a `try` statement. */
class Try : public Statement {
public:
    auto body() const { return child<hilti::Statement>(0); }
    auto catches() const { return children<try_::Catch>(1, {}); }

    void addCatch(ASTContext* ctx, try_::Catch* c) { addChild(ctx, c); }

    static auto create(ASTContext* ctx, Statement* body, const try_::Catches& catches, Meta meta = {}) {
        return ctx->make<Try>(ctx, node::flatten(body, catches), std::move(meta));
    }

protected:
    Try(ASTContext* ctx, Nodes children, Meta meta) : Statement(ctx, NodeTags, std::move(children), std::move(meta)) {}

    HILTI_NODE_1(statement::Try, Statement, final);
};

} // namespace hilti::statement
