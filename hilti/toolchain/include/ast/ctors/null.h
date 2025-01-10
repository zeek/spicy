// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/ctor.h>
#include <hilti/ast/types/null.h>

namespace hilti::ctor {

/** AST node for a `Null` ctor. */
class Null : public Ctor {
public:
    QualifiedType* type() const final { return child<QualifiedType>(0); }

    static auto create(ASTContext* ctx, const Meta& meta = {}) {
        return ctx->make<Null>(ctx, {QualifiedType::create(ctx, type::Null::create(ctx, meta), Constness::Const)},
                               meta);
    }

protected:
    Null(ASTContext* ctx, Nodes children, Meta meta) : Ctor(ctx, NodeTags, std::move(children), std::move(meta)) {}

    HILTI_NODE_1(ctor::Null, Ctor, final);
};

} // namespace hilti::ctor
