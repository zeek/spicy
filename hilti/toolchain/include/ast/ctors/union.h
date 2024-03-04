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
    ExpressionPtr value() const { return child<Expression>(1); }

    QualifiedTypePtr type() const final { return child<QualifiedType>(0); }

    static auto create(ASTContext* ctx, const QualifiedTypePtr& type, const ExpressionPtr& value,
                       const Meta& meta = {}) {
        return std::shared_ptr<Union>(new Union(ctx, {type, value}, meta));
    }

protected:
    Union(ASTContext* ctx, Nodes children, Meta meta) : Ctor(ctx, NodeTags, std::move(children), std::move(meta)) {}

    HILTI_NODE_1(ctor::Union, Ctor, final);
};

} // namespace hilti::ctor
