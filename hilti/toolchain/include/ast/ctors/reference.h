// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

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
    QualifiedTypePtr dereferencedType() const {
        return type()->type()->as<type::StrongReference>()->dereferencedType();
    }

    QualifiedTypePtr type() const final { return child<QualifiedType>(0); }

    static auto create(ASTContext* ctx, const QualifiedTypePtr& t, const Meta& meta = {}) {
        return CtorPtr(new StrongReference(ctx,
                                           {QualifiedType::create(ctx, type::StrongReference::create(ctx, t, meta),
                                                                  Constness::Const)},
                                           meta));
    }

protected:
    StrongReference(ASTContext* ctx, Nodes children, Meta meta)
        : Ctor(ctx, NodeTags, std::move(children), std::move(meta)) {}

    HILTI_NODE_1(ctor::StrongReference, Ctor, final);
};

/** AST node for a `weak_ref<T>` constructor value (which can only be null). */
class WeakReference : public Ctor {
public:
    QualifiedTypePtr dereferencedType() const { return type()->type()->as<type::WeakReference>()->dereferencedType(); }

    QualifiedTypePtr type() const final { return child<QualifiedType>(0); }

    static auto create(ASTContext* ctx, const QualifiedTypePtr& t, const Meta& meta = {}) {
        return CtorPtr(
            new WeakReference(ctx,
                              {QualifiedType::create(ctx, type::WeakReference::create(ctx, t, meta), Constness::Const)},
                              meta));
    }

protected:
    WeakReference(ASTContext* ctx, Nodes children, Meta meta)
        : Ctor(ctx, NodeTags, std::move(children), std::move(meta)) {}

    HILTI_NODE_1(ctor::WeakReference, Ctor, final);
};

/** AST node for a `value_ref<T>` constructor value. */
class ValueReference : public Ctor {
public:
    QualifiedTypePtr type() const final { return child<QualifiedType>(0); }
    ExpressionPtr expression() const { return child<Expression>(1); }

    QualifiedTypePtr dereferencedType() const { return type()->type()->as<type::ValueReference>()->dereferencedType(); }

    void setType(ASTContext* ctx, QualifiedTypePtr t) { setChild(ctx, 0, std::move(t)); }

    static auto create(ASTContext* ctx, const ExpressionPtr& expr, const Meta& meta = {}) {
        auto auto_ = QualifiedType::create(ctx, hilti::type::Auto::create(ctx), hilti::Constness::Const, meta);
        return std::shared_ptr<ValueReference>(new ValueReference(ctx, {auto_, expr}, meta));
    }

protected:
    ValueReference(ASTContext* ctx, Nodes children, Meta meta)
        : Ctor(ctx, NodeTags, std::move(children), std::move(meta)) {}

    HILTI_NODE_1(ctor::ValueReference, Ctor, final);
};

} // namespace hilti::ctor
