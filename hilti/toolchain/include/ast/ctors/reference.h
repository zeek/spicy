// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/ctor.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/types/auto.h>
#include <hilti/ast/types/reference.h>

namespace hilti::ctor {

/** AST node for a `strong_ref<T>` constructor value (which can only be null). */
class StrongReference : public Ctor {
public:
    QualifiedType* dereferencedType() const { return type()->type()->as<type::StrongReference>()->dereferencedType(); }

    QualifiedType* type() const final { return child<QualifiedType>(0); }

    static auto create(ASTContext* ctx, QualifiedType* t, const Meta& meta = {}) {
        return ctx->make<StrongReference>(ctx,
                                          {QualifiedType::create(ctx, type::StrongReference::create(ctx, t, meta),
                                                                 Constness::Const)},
                                          meta);
    }

protected:
    StrongReference(ASTContext* ctx, Nodes children, Meta meta)
        : Ctor(ctx, NodeTags, std::move(children), std::move(meta)) {}

    HILTI_NODE_1(ctor::StrongReference, Ctor, final);
};

/** AST node for a `weak_ref<T>` constructor value (which can only be null). */
class WeakReference : public Ctor {
public:
    QualifiedType* dereferencedType() const { return type()->type()->as<type::WeakReference>()->dereferencedType(); }

    QualifiedType* type() const final { return child<QualifiedType>(0); }

    static auto create(ASTContext* ctx, QualifiedType* t, const Meta& meta = {}) {
        return ctx->make<WeakReference>(ctx,
                                        {QualifiedType::create(ctx, type::WeakReference::create(ctx, t, meta),
                                                               Constness::Const)},
                                        meta);
    }

protected:
    WeakReference(ASTContext* ctx, Nodes children, Meta meta)
        : Ctor(ctx, NodeTags, std::move(children), std::move(meta)) {}

    HILTI_NODE_1(ctor::WeakReference, Ctor, final);
};

/** AST node for a `value_ref<T>` constructor value. */
class ValueReference : public Ctor {
public:
    QualifiedType* type() const final { return child<QualifiedType>(0); }
    Expression* expression() const { return child<Expression>(1); }

    QualifiedType* dereferencedType() const { return type()->type()->as<type::ValueReference>()->dereferencedType(); }

    void setType(ASTContext* ctx, QualifiedType* t) { setChild(ctx, 0, t); }

    static auto create(ASTContext* ctx, Expression* expr, Meta meta = {}) {
        auto* auto_ = QualifiedType::create(ctx, hilti::type::Auto::create(ctx), hilti::Constness::Const, meta);
        return ctx->make<ValueReference>(ctx, {auto_, expr}, std::move(meta));
    }

protected:
    ValueReference(ASTContext* ctx, Nodes children, Meta meta)
        : Ctor(ctx, NodeTags, std::move(children), std::move(meta)) {}

    HILTI_NODE_1(ctor::ValueReference, Ctor, final);
};

} // namespace hilti::ctor
