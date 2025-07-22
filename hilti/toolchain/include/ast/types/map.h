// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/forward.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/tuple.h>
#include <hilti/ast/types/unknown.h>

namespace hilti::type {

namespace map {

/** AST node for a map iterator type. */
class Iterator : public UnqualifiedType {
public:
    std::string_view typeClass() const final { return "iterator<map>"; }

    QualifiedType* keyType() const { return dereferencedType()->type()->as<type::Tuple>()->elements()[0]->type(); }
    QualifiedType* valueType() const { return dereferencedType()->type()->as<type::Tuple>()->elements()[1]->type(); }
    QualifiedType* dereferencedType() const final { return child<QualifiedType>(0); }

    bool isAliasingType() const final { return true; }
    bool isAllocable() const final { return true; }
    bool isMutable() const final { return true; }

    static auto create(ASTContext* ctx, QualifiedType* ktype, QualifiedType* vtype, const Meta& meta = {}) {
        return ctx->make<Iterator>(ctx,
                                   {QualifiedType::create(ctx, type::Tuple::create(ctx, QualifiedTypes{ktype, vtype}),
                                                          Constness::Const)},
                                   meta);
    }

    static auto create(ASTContext* ctx, Wildcard _, const Meta& meta = Meta()) {
        return ctx->make<Iterator>(
            ctx, Wildcard(),
            {QualifiedType::create(
                ctx,
                type::Tuple::create(ctx, QualifiedTypes{QualifiedType::create(ctx, type::Unknown::create(ctx, meta),
                                                                              Constness::Const),
                                                        QualifiedType::create(ctx, type::Unknown::create(ctx, meta),
                                                                              Constness::Const)}),
                Constness::Const)},
            meta);
    }

protected:
    Iterator(ASTContext* ctx, Nodes children, Meta meta)
        : UnqualifiedType(ctx, NodeTags, {}, std::move(children), std::move(meta)) {}
    Iterator(ASTContext* ctx, Wildcard _, Nodes children, Meta meta)
        : UnqualifiedType(ctx, NodeTags, Wildcard(), {"iterator(map(*))"}, std::move(children), std::move(meta)) {}

    bool isResolved(node::CycleDetector* cd) const final {
        return keyType()->isResolved(cd) && valueType()->isResolved(cd);
    }

    HILTI_NODE_1(type::map::Iterator, UnqualifiedType, final);
};

} // namespace map

/** AST node for a `map` type. */
class Map : public UnqualifiedType {
public:
    QualifiedType* keyType() const { return iteratorType()->type()->as<map::Iterator>()->keyType(); }
    QualifiedType* valueType() const { return iteratorType()->type()->as<map::Iterator>()->valueType(); }

    std::string_view typeClass() const final { return "map"; }

    QualifiedType* iteratorType() const final { return child<QualifiedType>(0); }
    QualifiedType* elementType() const final { return valueType(); }

    bool isAllocable() const final { return true; }
    bool isMutable() const final { return true; }
    bool isResolved(node::CycleDetector* cd) const final { return iteratorType()->isResolved(cd); }

    static auto create(ASTContext* ctx, QualifiedType* ktype, QualifiedType* vtype, const Meta& meta = {}) {
        return ctx->make<Map>(ctx,
                              {QualifiedType::create(ctx, map::Iterator::create(ctx, ktype, vtype, meta),
                                                     Constness::Mutable)},
                              meta);
    }

    static auto create(ASTContext* ctx, Wildcard _, const Meta& m = Meta()) {
        return ctx->make<Map>(ctx, Wildcard(),
                              {QualifiedType::create(ctx, map::Iterator::create(ctx, Wildcard(), m),
                                                     Constness::Mutable)},
                              m);
    }

protected:
    Map(ASTContext* ctx, Nodes children, Meta meta)
        : UnqualifiedType(ctx, NodeTags, {}, std::move(children), std::move(meta)) {}
    Map(ASTContext* ctx, Wildcard _, Nodes children, Meta meta)
        : UnqualifiedType(ctx, NodeTags, Wildcard(), {"map(*)"}, std::move(children), std::move(meta)) {}


    void newlyQualified(const QualifiedType* qtype) const final {
        valueType()->setConst(qtype->constness());
        iteratorType()->type()->dereferencedType()->setConst(qtype->constness());
    }

    HILTI_NODE_1(type::Map, UnqualifiedType, final);
};

} // namespace hilti::type
