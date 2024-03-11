// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/ctor.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/forward.h>
#include <hilti/ast/type.h>

namespace hilti::ctor {

/** AST node for a `exception` ctor. */
class Exception : public Ctor {
public:
    auto value() const { return child<Expression>(1); }
    auto location() const { return childTryAs<Expression>(2); }

    QualifiedType* type() const final { return child<QualifiedType>(0); }

    /** Constructs a exception value of a given type. */
    static auto create(ASTContext* ctx, UnqualifiedType* type, Expression* value, const Meta& meta = {}) {
        return ctx->make<Exception>(ctx, {QualifiedType::create(ctx, type, Constness::Const, meta), value, nullptr},
                                    meta);
    }

    static auto create(ASTContext* ctx, UnqualifiedType* type, Expression* value, Expression* location,
                       const Meta& meta = {}) {
        return ctx->make<Exception>(ctx, {QualifiedType::create(ctx, type, Constness::Const, meta), value, location},
                                    meta);
    }

protected:
    Exception(ASTContext* ctx, Nodes children, Meta meta) : Ctor(ctx, NodeTags, std::move(children), std::move(meta)) {}

    HILTI_NODE_1(ctor::Exception, Ctor, final);
};

} // namespace hilti::ctor
