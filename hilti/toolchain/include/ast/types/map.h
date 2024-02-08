// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
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

    QualifiedTypePtr keyType() const { return dereferencedType()->type()->as<type::Tuple>()->elements()[0]->type(); }
    QualifiedTypePtr valueType() const { return dereferencedType()->type()->as<type::Tuple>()->elements()[1]->type(); }
    QualifiedTypePtr dereferencedType() const final { return child<QualifiedType>(0); }

    bool isAllocable() const final { return true; }
    bool isMutable() const final { return true; }

    static auto create(ASTContext* ctx, const QualifiedTypePtr& ktype, const QualifiedTypePtr& vtype,
                       const Meta& meta = {}) {
        return std::shared_ptr<Iterator>(
            new Iterator(ctx, {QualifiedType::create(ctx, type::Tuple::create(ctx, {ktype, vtype}), Constness::Const)},
                         meta));
    }

    static auto create(ASTContext* ctx, Wildcard _, const Meta& meta = Meta()) {
        return std::shared_ptr<Iterator>(
            new Iterator(ctx, Wildcard(),
                         {QualifiedType::create(
                             ctx,
                             type::Tuple::create(ctx, {QualifiedType::create(ctx, type::Unknown::create(ctx, meta),
                                                                             Constness::Const),
                                                       QualifiedType::create(ctx, type::Unknown::create(ctx, meta),
                                                                             Constness::Const)}),
                             Constness::Const)},
                         meta));
    }

protected:
    Iterator(ASTContext* ctx, Nodes children, Meta meta)
        : UnqualifiedType(ctx, {}, std::move(children), std::move(meta)) {}
    Iterator(ASTContext* ctx, Wildcard _, Nodes children, Meta meta)
        : UnqualifiedType(ctx, Wildcard(), {"iterator(map(*))"}, std::move(children), std::move(meta)) {}

    bool isResolved(node::CycleDetector* cd) const final {
        return keyType()->isResolved(cd) && valueType()->isResolved(cd);
    }

    HILTI_NODE(hilti, Iterator)
};

} // namespace map

/** AST node for a `map` type. */
class Map : public UnqualifiedType {
public:
    QualifiedTypePtr keyType() const { return iteratorType()->type()->as<map::Iterator>()->keyType(); }
    QualifiedTypePtr valueType() const { return iteratorType()->type()->as<map::Iterator>()->valueType(); }

    std::string_view typeClass() const final { return "map"; }

    QualifiedTypePtr iteratorType() const final { return child<QualifiedType>(0); }
    QualifiedTypePtr elementType() const final { return valueType(); }

    bool isAllocable() const final { return true; }
    bool isMutable() const final { return true; }
    bool isResolved(node::CycleDetector* cd) const final { return iteratorType()->isResolved(cd); }

    static auto create(ASTContext* ctx, const QualifiedTypePtr& ktype, const QualifiedTypePtr& vtype,
                       const Meta& meta = {}) {
        return std::shared_ptr<Map>(
            new Map(ctx,
                    {QualifiedType::create(ctx, map::Iterator::create(ctx, ktype, vtype, meta), Constness::NonConst)},
                    meta));
    }

    static auto create(ASTContext* ctx, Wildcard _, const Meta& m = Meta()) {
        return std::shared_ptr<Map>(
            new Map(ctx, Wildcard(),
                    {QualifiedType::create(ctx, map::Iterator::create(ctx, Wildcard(), m), Constness::NonConst)}, m));
    }

protected:
    Map(ASTContext* ctx, Nodes children, Meta meta) : UnqualifiedType(ctx, {}, std::move(children), std::move(meta)) {}
    Map(ASTContext* ctx, Wildcard _, Nodes children, Meta meta)
        : UnqualifiedType(ctx, Wildcard(), {"map(*)"}, std::move(children), std::move(meta)) {}


    void newlyQualified(const QualifiedType* qtype) const final {
        valueType()->setConst(qtype->constness());
        iteratorType()->type()->dereferencedType()->setConst(qtype->constness());
    }

    HILTI_NODE(hilti, Map)
};

} // namespace hilti::type
