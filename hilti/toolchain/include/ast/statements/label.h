// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <algorithm>
#include <utility>

#include <hilti/ast/id.h>
#include <hilti/ast/statement.h>
#include <hilti/ast/statements/block.h>

namespace hilti::statement {

/**
 * AST node for a label that a `goto` can jump to. Labels are only created
 * programmatically; there's no HILTI syntax for them. A label must appear
 * directly in a function's top-level body.
 */
class Label : public Statement {
public:
    const auto& id() const { return _id; }

    node::Properties properties() const final {
        auto p = node::Properties{{"id", _id}};
        return Statement::properties() + std::move(p);
    }

    static auto create(ASTContext* ctx, ID id, Meta meta = {}) {
        return ctx->make<Label>(ctx, {}, std::move(id), std::move(meta));
    }

protected:
    Label(ASTContext* ctx, Nodes children, ID id, Meta meta)
        : Statement(ctx, NodeTags, std::move(children), std::move(meta)), _id(std::move(id)) {}

    HILTI_NODE_1(statement::Label, Statement, final);

private:
    ID _id;
};

namespace label {

/** Returns the label with a given ID among a function body's top-level statements, or null if there's none. */
inline Label* find(const Block& body, const ID& id) {
    for ( auto* s : body.children() ) {
        if ( auto* l = s ? s->tryAs<Label>() : nullptr; l && l->id() == id )
            return l;
    }

    return nullptr;
}

/** Returns true if a function body has any top-level labels. */
inline bool hasLabels(const Block& body) {
    return std::ranges::any_of(body.children(), [](const auto* s) { return s && s->template isA<Label>(); });
}

} // namespace label

} // namespace hilti::statement
