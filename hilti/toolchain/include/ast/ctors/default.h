// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/ctor.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/type.h>

namespace hilti::ctor {

/** AST node for a `default` ctor. */
class Default : public Ctor {
public:
    auto typeArguments() const { return children<Expression>(1, {}); }

    QualifiedTypePtr type() const final { return child<QualifiedType>(0); }

    void setTypeArguments(ASTContext* ctx, Expressions exprs) {
        removeChildren(1, {});
        addChildren(ctx, std::move(exprs));
    }

    /** Constructs a default value of a given type. */
    static auto create(ASTContext* ctx, const UnqualifiedTypePtr& type, const Meta& meta = {}) {
        return std::shared_ptr<Default>(
            new Default(ctx, {QualifiedType::create(ctx, type, Constness::Const, meta)}, meta));
    }

    /**
     * Constructs a default value of a given type, passing specified arguments to
     * types with parameters.
     */
    static auto create(ASTContext* ctx, const UnqualifiedTypePtr& type, Expressions type_args, const Meta& meta = {}) {
        return CtorPtr(
            new Default(ctx,
                        node::flatten(QualifiedType::create(ctx, type, Constness::Const, meta), std::move(type_args)),
                        meta));
    }

protected:
    Default(ASTContext* ctx, Nodes children, Meta meta) : Ctor(ctx, NodeTags, std::move(children), std::move(meta)) {}

    HILTI_NODE_1(ctor::Default, Ctor, final);
};

} // namespace hilti::ctor
