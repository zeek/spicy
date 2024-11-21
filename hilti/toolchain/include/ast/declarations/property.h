// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>
#include <vector>

#include <hilti/ast/declaration.h>
#include <hilti/ast/expression.h>

namespace hilti::declaration {

/** AST node for a property declaration. */
class Property : public Declaration {
public:
    auto expression() const { return childTryAs<::hilti::Expression>(0); }

    std::string_view displayName() const final { return "property"; }

    static auto create(ASTContext* ctx, ID id, Meta meta = {}) {
        return ctx->make<Property>(ctx, {}, std::move(id), std::move(meta));
    }

    static auto create(ASTContext* ctx, ID id, hilti::Expression* expr, Meta meta = {}) {
        return ctx->make<Property>(ctx, {expr}, std::move(id), std::move(meta));
    }

protected:
    Property(ASTContext* ctx, Nodes children, ID id, Meta meta)
        : Declaration(ctx, NodeTags, std::move(children), std::move(id), Linkage::Private, std::move(meta)) {}

    HILTI_NODE_1(declaration::Property, Declaration, final);
};

using Properties = std::vector<Property>;

} // namespace hilti::declaration
