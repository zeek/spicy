// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>
#include <utility>

#include <hilti/ast/attribute.h>
#include <hilti/ast/declaration.h>
#include <hilti/ast/expression.h>

namespace hilti::declaration {

/** AST node for a expression declaration. */
class Expression : public Declaration {
public:
    auto expression() const { return child<hilti::Expression>(0); }
    auto attributes() const { return child<AttributeSet>(1); }

    std::string_view displayName() const final { return "expression"; }

    static auto create(ASTContext* ctx, ID id, hilti::Expression* expr, declaration::Linkage linkage, Meta meta = {}) {
        return ctx->make<Expression>(ctx, {expr, AttributeSet::create(ctx)}, std::move(id), linkage, std::move(meta));
    }


protected:
    Expression(ASTContext* ctx, Nodes children, ID id, declaration::Linkage linkage, Meta meta)
        : Declaration(ctx, NodeTags, std::move(children), std::move(id), linkage, std::move(meta)) {}

    HILTI_NODE_1(declaration::Expression, Declaration, final);
};

} // namespace hilti::declaration
