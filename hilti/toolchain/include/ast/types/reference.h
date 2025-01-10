// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/forward.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/null.h>
#include <hilti/ast/types/unknown.h>

namespace hilti::type {

/** AST node for a `strong_ref<T>` type. */
class StrongReference : public UnqualifiedType {
public:
    std::string_view typeClass() const final { return "strong_ref"; }

    QualifiedType* dereferencedType() const final { return child(0)->as<QualifiedType>(); }

    bool isAllocable() const final { return true; }
    bool isReferenceType() const final { return true; }
    bool isResolved(node::CycleDetector* cd) const final { return dereferencedType()->isResolved(cd); }

    static auto create(ASTContext* ctx, QualifiedType* type, Meta meta = {}) {
        return ctx->make<StrongReference>(ctx, {type}, std::move(meta));
    }

    static auto create(ASTContext* ctx, Wildcard _, const Meta& m = Meta()) {
        return ctx->make<StrongReference>(ctx, Wildcard(),
                                          {QualifiedType::create(ctx, type::Null::create(ctx, m), Constness::Const)},
                                          m);
    }

protected:
    StrongReference(ASTContext* ctx, Nodes children, Meta meta)
        : UnqualifiedType(ctx, NodeTags, {}, std::move(children), std::move(meta)) {}
    StrongReference(ASTContext* ctx, Wildcard _, Nodes children, Meta meta)
        : UnqualifiedType(ctx, NodeTags, Wildcard(), {"strong_ref(*)"}, std::move(children), std::move(meta)) {}

    HILTI_NODE_1(type::StrongReference, UnqualifiedType, final);
};

/** AST node for a `weak_ref<T>` type. */
class WeakReference : public UnqualifiedType {
public:
    std::string_view typeClass() const final { return "weak_ref"; }

    QualifiedType* dereferencedType() const final { return child(0)->as<QualifiedType>(); }

    bool isAllocable() const final { return true; }
    bool isReferenceType() const final { return true; }

    static auto create(ASTContext* ctx, QualifiedType* type, Meta meta = {}) {
        return ctx->make<WeakReference>(ctx, {type}, std::move(meta));
    }

    static auto create(ASTContext* ctx, Wildcard _, const Meta& m = Meta()) {
        return ctx->make<WeakReference>(ctx, Wildcard(),
                                        {QualifiedType::create(ctx, type::Null::create(ctx, m), Constness::Const)}, m);
    }

protected:
    WeakReference(ASTContext* ctx, Nodes children, Meta meta)
        : UnqualifiedType(ctx, NodeTags, {}, std::move(children), std::move(meta)) {}
    WeakReference(ASTContext* ctx, Wildcard _, Nodes children, Meta meta)
        : UnqualifiedType(ctx, NodeTags, Wildcard(), {"weak_ref(*)"}, std::move(children), std::move(meta)) {}

    bool isResolved(node::CycleDetector* cd) const final { return dereferencedType()->isResolved(cd); }

    HILTI_NODE_1(type::WeakReference, UnqualifiedType, final);
};

/** AST node for a `value_ref<T>` type. */
class ValueReference : public UnqualifiedType {
public:
    std::string_view typeClass() const final { return "value_ref"; }

    QualifiedType* dereferencedType() const final { return child(0)->as<QualifiedType>(); }

    bool isAllocable() const final { return true; }
    bool isReferenceType() const final { return true; }

    static auto create(ASTContext* ctx, QualifiedType* type, Meta meta = {}) {
        return ctx->make<ValueReference>(ctx, {type}, std::move(meta));
    }

    static auto create(ASTContext* ctx, Wildcard _, const Meta& m = Meta()) {
        return ctx->make<ValueReference>(ctx, Wildcard(),
                                         {QualifiedType::create(ctx, type::Null::create(ctx, m), Constness::Const)}, m);
    }

protected:
    ValueReference(ASTContext* ctx, Nodes children, Meta meta)
        : UnqualifiedType(ctx, NodeTags, {}, std::move(children), std::move(meta)) {}
    ValueReference(ASTContext* ctx, Wildcard _, Nodes children, Meta meta)
        : UnqualifiedType(ctx, NodeTags, Wildcard(), {"value_ref(*)"}, std::move(children), std::move(meta)) {}

    bool isResolved(node::CycleDetector* cd) const final { return dereferencedType()->isResolved(cd); }

    HILTI_NODE_1(type::ValueReference, UnqualifiedType, final);
};

} // namespace hilti::type
