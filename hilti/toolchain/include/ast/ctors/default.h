// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/ctor.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/type.h>

namespace hilti::ctor {

/** AST node for a `default` ctor. */
class Default : public Ctor {
public:
    auto typeArguments() const { return children<Expression>(1, {}); }

    QualifiedType* type() const final { return child<QualifiedType>(0); }

    void setTypeArguments(ASTContext* ctx, const Expressions& exprs) {
        removeChildren(1, {});
        addChildren(ctx, exprs);
    }

    /** Constructs a default value of a given type. */
    static auto create(ASTContext* ctx, UnqualifiedType* type, const Meta& meta = {}) {
        return ctx->make<Default>(ctx, {QualifiedType::create(ctx, type, Constness::Const, meta)}, meta);
    }

    /**
     * Constructs a default value of a given type, passing specified arguments to
     * types with parameters.
     */
    static auto create(ASTContext* ctx, UnqualifiedType* type, const Expressions& type_args, const Meta& meta = {}) {
        return ctx->make<Default>(ctx,
                                  node::flatten(QualifiedType::create(ctx, type, Constness::Const, meta), type_args),
                                  meta);
    }

protected:
    Default(ASTContext* ctx, Nodes children, Meta meta) : Ctor(ctx, NodeTags, std::move(children), std::move(meta)) {}

    HILTI_NODE_1(ctor::Default, Ctor, final);
};

} // namespace hilti::ctor
