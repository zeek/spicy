// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/type.h>
#include <hilti/ast/types/unknown.h>

namespace hilti::type {

namespace vector {

/** AST node for a vector iterator type. */
class Iterator : public UnqualifiedType {
public:
    std::string_view typeClass() const final { return "iterator<vector>"; }

    QualifiedType* dereferencedType() const final { return child<QualifiedType>(0); }

    bool isAllocable() const final { return true; }
    bool isMutable() const final { return true; }
    bool isResolved(node::CycleDetector* cd) const final { return dereferencedType()->isResolved(cd); }

    static auto create(ASTContext* ctx, QualifiedType* etype, Meta meta = {}) {
        return ctx->make<Iterator>(ctx, {etype}, std::move(meta));
    }

    static auto create(ASTContext* ctx, Wildcard _, const Meta& m = Meta()) {
        return ctx->make<Iterator>(ctx, Wildcard(),
                                   {QualifiedType::create(ctx, type::Unknown::create(ctx, m), Constness::Const)}, m);
    }

protected:
    Iterator(ASTContext* ctx, Nodes children, Meta meta)
        : UnqualifiedType(ctx, NodeTags, {}, std::move(children), std::move(meta)) {}
    Iterator(ASTContext* ctx, Wildcard _, Nodes children, Meta meta)
        : UnqualifiedType(ctx, NodeTags, Wildcard(), {"iterator(vector(*))"}, std::move(children), std::move(meta)) {}


    HILTI_NODE_1(type::vector::Iterator, UnqualifiedType, final);
};

} // namespace vector

/** AST node for a `vector` type. */
class Vector : public UnqualifiedType {
public:
    QualifiedType* elementType() const final { return iteratorType()->type()->dereferencedType(); }
    QualifiedType* iteratorType() const final { return child<QualifiedType>(0); }

    std::string_view typeClass() const final { return "vector"; }

    bool isAllocable() const final { return true; }
    bool isMutable() const final { return true; }
    bool isResolved(node::CycleDetector* cd) const final { return iteratorType()->isResolved(cd); }

    static auto create(ASTContext* ctx, QualifiedType* t, const Meta& meta = {}) {
        return ctx->make<Vector>(ctx,
                                 {QualifiedType::create(ctx, vector::Iterator::create(ctx, t, meta),
                                                        Constness::Mutable)},
                                 meta);
    }

    static auto create(ASTContext* ctx, Wildcard _, const Meta& m = Meta()) {
        return ctx->make<Vector>(ctx, Wildcard(),
                                 {QualifiedType::create(ctx, vector::Iterator::create(ctx, Wildcard(), m),
                                                        Constness::Mutable)},
                                 m);
    }

protected:
    Vector(ASTContext* ctx, Nodes children, Meta meta)
        : UnqualifiedType(ctx, NodeTags, {}, std::move(children), std::move(meta)) {}
    Vector(ASTContext* ctx, Wildcard _, Nodes children, Meta meta)
        : UnqualifiedType(ctx, NodeTags, Wildcard(), {"vector(*)"}, std::move(children), std::move(meta)) {}


    void newlyQualified(const QualifiedType* qtype) const final { elementType()->setConst(qtype->constness()); }

    HILTI_NODE_1(type::Vector, UnqualifiedType, final);
};

} // namespace hilti::type
