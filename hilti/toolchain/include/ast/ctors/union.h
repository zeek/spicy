// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/ctor.h>
#include <hilti/ast/types/union.h>

namespace hilti::ctor {

/** AST node for a `union` ctor. */
class Union : public Ctor {
public:
    /** Returns the value to initialize the unit with. */
    Expression* value() const { return child<Expression>(1); }

    QualifiedType* type() const final { return child<QualifiedType>(0); }

    static auto create(ASTContext* ctx, QualifiedType* type, Expression* value, Meta meta = {}) {
        return ctx->make<Union>(ctx, {type, value}, std::move(meta));
    }

protected:
    Union(ASTContext* ctx, Nodes children, Meta meta) : Ctor(ctx, NodeTags, std::move(children), std::move(meta)) {}

    HILTI_NODE_1(ctor::Union, Ctor, final);
};

} // namespace hilti::ctor
