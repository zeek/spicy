// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/type.h>
#include <hilti/ast/types/integer.h>

namespace hilti::type {

namespace bytes {

/** AST node for a bytes iterator type. */
class Iterator : public UnqualifiedType {
public:
    QualifiedTypePtr dereferencedType() const final { return child<QualifiedType>(0); }

    static auto create(ASTContext* ctx, const Meta& meta = {}) {
        auto etype = QualifiedType::create(ctx, type::UnsignedInteger::create(ctx, 8, meta), Constness::Const, meta);
        return std::shared_ptr<Iterator>(new Iterator(ctx, {etype}, meta));
    }

    std::string_view typeClass() const final { return "iterator<bytes>"; }

    bool isAllocable() const final { return true; }
    bool isMutable() const final { return true; }

protected:
    Iterator(ASTContext* ctx, Nodes children, Meta meta)
        : UnqualifiedType(ctx, {"iterator(bytes)"}, std::move(children), std::move(meta)) {}

    HILTI_NODE(hilti, Iterator)
};

} // namespace bytes

/** AST node for a `bytes` type. */
class Bytes : public UnqualifiedType {
public:
    QualifiedTypePtr elementType() const final { return iteratorType()->type()->dereferencedType(); }
    QualifiedTypePtr iteratorType() const final { return child<QualifiedType>(0); }

    static auto create(ASTContext* ctx, const Meta& meta = {}) {
        return std::shared_ptr<Bytes>(
            new Bytes(ctx, {QualifiedType::create(ctx, bytes::Iterator::create(ctx, meta), Constness::Mutable)}, meta));
    }

    std::string_view typeClass() const final { return "bytes"; }

    bool isAllocable() const final { return true; }
    bool isMutable() const final { return true; }
    bool isSortable() const final { return true; }

protected:
    Bytes(ASTContext* ctx, Nodes children, Meta meta)
        : UnqualifiedType(ctx, {"bytes"}, std::move(children), std::move(meta)) {}

    void newlyQualified(const QualifiedType* qtype) const final { elementType()->setConst(qtype->constness()); }

    HILTI_NODE(hilti, Bytes)
};

} // namespace hilti::type
