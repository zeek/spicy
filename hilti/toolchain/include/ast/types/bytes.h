// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/type.h>
#include <hilti/ast/types/integer.h>

namespace hilti::type {

namespace bytes {

/** AST node for a bytes iterator type. */
class Iterator : public UnqualifiedType {
public:
    QualifiedType* dereferencedType() const final { return child<QualifiedType>(0); }

    static auto create(ASTContext* ctx, Meta meta = {}) {
        auto* etype = QualifiedType::create(ctx, type::UnsignedInteger::create(ctx, 8, meta), Constness::Const, meta);
        return ctx->make<Iterator>(ctx, {etype}, std::move(meta));
    }

    std::string_view typeClass() const final { return "iterator<bytes>"; }

    bool isAliasingType() const final { return true; }
    bool isAllocable() const final { return true; }
    bool isMutable() const final { return true; }

protected:
    Iterator(ASTContext* ctx, Nodes children, Meta meta)
        : UnqualifiedType(ctx, NodeTags, {"iterator(bytes)"}, std::move(children), std::move(meta)) {}

    HILTI_NODE_1(type::bytes::Iterator, UnqualifiedType, final);
};

} // namespace bytes

/** AST node for a `bytes` type. */
class Bytes : public UnqualifiedType {
public:
    QualifiedType* elementType() const final { return iteratorType()->type()->dereferencedType(); }
    QualifiedType* iteratorType() const final { return child<QualifiedType>(0); }

    static auto create(ASTContext* ctx, const Meta& meta = {}) {
        return ctx->make<Bytes>(ctx,
                                {QualifiedType::create(ctx, bytes::Iterator::create(ctx, meta), Constness::Mutable)},
                                meta);
    }

    std::string_view typeClass() const final { return "bytes"; }

    bool isAllocable() const final { return true; }
    bool isMutable() const final { return true; }
    bool isSortable() const final { return true; }

protected:
    Bytes(ASTContext* ctx, Nodes children, Meta meta)
        : UnqualifiedType(ctx, NodeTags, {"bytes"}, std::move(children), std::move(meta)) {}

    void newlyQualified(const QualifiedType* qtype) const final { elementType()->setConst(qtype->constness()); }

    HILTI_NODE_1(type::Bytes, UnqualifiedType, final);
};

} // namespace hilti::type
