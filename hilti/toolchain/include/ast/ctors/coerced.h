// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/ctor.h>

namespace hilti::ctor {

/** AST node for a constructor that's been coerced from one type to another. */
class Coerced : public Ctor {
public:
    auto originalCtor() const { return child<Ctor>(0); }
    auto coercedCtor() const { return child<Ctor>(1); }

    QualifiedType* type() const final { return coercedCtor()->type(); }

    static auto create(ASTContext* ctx, Ctor* orig, Ctor* new_, Meta meta = {}) {
        return ctx->make<Coerced>(ctx, {orig, new_}, std::move(meta));
    }

protected:
    Coerced(ASTContext* ctx, Nodes children, Meta meta) : Ctor(ctx, NodeTags, std::move(children), std::move(meta)) {}

    HILTI_NODE_1(ctor::Coerced, Ctor, final);
};

} // namespace hilti::ctor
