
// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/type.h>
#include <hilti/ast/types/unknown.h>

namespace hilti::type {

namespace set {

/** AST node for a set iterator type. */
class Iterator : public UnqualifiedType {
public:
    std::string_view typeClass() const final { return "iterator<set>"; }

    QualifiedType* dereferencedType() const override { return child<QualifiedType>(0); }

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
        : UnqualifiedType(ctx, NodeTags, Wildcard(), {"iterator(set(*))"}, std::move(children), std::move(meta)) {}


    HILTI_NODE_1(type::set::Iterator, UnqualifiedType, final);
};

} // namespace set

/** AST node for a `set` type. */
class Set : public UnqualifiedType {
public:
    std::string_view typeClass() const final { return "set"; }

    QualifiedType* elementType() const final { return iteratorType()->type()->dereferencedType(); }
    QualifiedType* iteratorType() const final { return child<QualifiedType>(0); }

    bool isAllocable() const override { return true; }
    bool isMutable() const override { return true; }
    bool isResolved(node::CycleDetector* cd) const final { return iteratorType()->isResolved(cd); }

    static auto create(ASTContext* ctx, QualifiedType* t, const Meta& meta = {}) {
        return ctx->make<Set>(ctx,
                              {QualifiedType::create(ctx, set::Iterator::create(ctx, t, meta), Constness::Mutable)},
                              meta);
    }

    static auto create(ASTContext* ctx, Wildcard _, const Meta& m = Meta()) {
        return ctx->make<Set>(ctx, Wildcard(),
                              {QualifiedType::create(ctx, set::Iterator::create(ctx, Wildcard(), m),
                                                     Constness::Mutable)},
                              m);
    }

protected:
    Set(ASTContext* ctx, Nodes children, Meta meta)
        : UnqualifiedType(ctx, NodeTags, {}, std::move(children), std::move(meta)) {}
    Set(ASTContext* ctx, Wildcard _, Nodes children, Meta meta)
        : UnqualifiedType(ctx, NodeTags, Wildcard(), {"set(*)"}, std::move(children), std::move(meta)) {}


    void newlyQualified(const QualifiedType* qtype) const final { elementType()->setConst(qtype->constness()); }

    HILTI_NODE_1(type::Set, UnqualifiedType, final);
};

} // namespace hilti::type
