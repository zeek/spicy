// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/id.h>
#include <hilti/ast/statement.h>
#include <hilti/ast/statements/label.h>

namespace hilti::statement {

/**
 * AST node for a `goto` statement jumping to a label of the same function.
 * Like labels, gotos are only created programmatically; there's no HILTI
 * syntax for them.
 */
class Goto : public Statement {
public:
    /** Returns the ID of the label this `goto` jumps to. */
    const auto& target() const { return _target; }

    /**
     * Returns the label that this `goto` refers to, or null if not yet
     * linked. This will be set once the resolver has finished.
     */
    Label* linkedLabel() const { return _label; }

    /**
     * Record the label that this `goto` refers to.
     *
     * This is normally called only by the resolver.
     *
     * @param label the label this `goto` is linked to
     */
    void setLinkedLabel(Label* label) { _label = label; }

    node::Properties properties() const final {
        auto p = node::Properties{{"target", _target}};

        if ( _label )
            p.insert({"label", util::fmt("%p", _label->identity())});

        return Statement::properties() + std::move(p);
    }

    static auto create(ASTContext* ctx, ID target, Meta meta = {}) {
        return ctx->make<Goto>(ctx, {}, std::move(target), std::move(meta));
    }

protected:
    Goto(ASTContext* ctx, Nodes children, ID target, Meta meta)
        : Statement(ctx, NodeTags, std::move(children), std::move(meta)), _target(std::move(target)) {}

    HILTI_NODE_1(statement::Goto, Statement, final);

private:
    ID _target;
    Label* _label = nullptr;
};

} // namespace hilti::statement
