// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/statement.h>

namespace hilti::statement {

/** AST node for a `break` statement. */
class Break : public Statement {
public:
    /**
     * Returns the loop statement that this `break` refers to, or null if not
     * yet linked. This will be set once the resolver has finished.
     */
    Statement* linkedLoop() const { return _loop; }

    /**
     * Record the enclosing loop statement that this `break` refers to.
     *
     * This is normally called only by the resolver.
     *
     * @param loop the loop statement this `break` is linked to
     */
    void setLinkedLoop(Statement* loop) { _loop = loop; }

    node::Properties properties() const final {
        node::Properties properties;

        if ( _loop )
            properties = {{"loop", util::fmt("%p", _loop->identity())}};

        return properties + Statement::properties();
    }

    static auto create(ASTContext* ctx, Meta meta = {}) { return ctx->make<Break>(ctx, {}, std::move(meta)); }

protected:
    Break(ASTContext* ctx, Nodes children, Meta meta)
        : Statement(ctx, NodeTags, std::move(children), std::move(meta)) {}

    HILTI_NODE_1(statement::Break, Statement, final);

private:
    Statement* _loop = nullptr;
};

} // namespace hilti::statement
