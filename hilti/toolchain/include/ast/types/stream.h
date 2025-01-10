// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/forward.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/integer.h>

namespace hilti::type {

namespace stream {

/** AST node for a stream iterator type. */
class Iterator : public UnqualifiedType {
public:
    std::string_view typeClass() const final { return "iterator<stream>"; }
    QualifiedType* dereferencedType() const final { return child<QualifiedType>(0); }

    bool isAllocable() const final { return true; }
    bool isMutable() const final { return true; }

    static auto create(ASTContext* ctx, Meta meta = {}) {
        auto etype = QualifiedType::create(ctx, type::UnsignedInteger::create(ctx, 8, meta), Constness::Mutable, meta);
        return ctx->make<Iterator>(ctx, {etype}, std::move(meta));
    }

protected:
    Iterator(ASTContext* ctx, Nodes children, Meta meta)
        : UnqualifiedType(ctx, NodeTags, {"iterator(stream)"}, std::move(children), std::move(meta)) {}

    HILTI_NODE_1(type::stream::Iterator, UnqualifiedType, final);
};

/** AST node for a stream view type. */
class View : public UnqualifiedType {
public:
    std::string_view typeClass() const final { return "view::stream"; }

    bool isAllocable() const final { return true; }
    bool isMutable() const final { return true; }

    QualifiedType* elementType() const final { return iteratorType()->type()->dereferencedType(); }
    QualifiedType* iteratorType() const final { return child<QualifiedType>(0); }

    static auto create(ASTContext* ctx, const Meta& meta = {}) {
        return ctx->make<View>(ctx, {QualifiedType::create(ctx, Iterator::create(ctx, meta), Constness::Mutable)},
                               meta);
    }

protected:
    View(ASTContext* ctx, Nodes children, Meta meta)
        : UnqualifiedType(ctx, NodeTags, {"view::stream"}, std::move(children), std::move(meta)) {}

    HILTI_NODE_1(type::stream::View, UnqualifiedType, final);
};

} // namespace stream

/** AST node for a `stream` type. */
class Stream : public UnqualifiedType {
public:
    std::string_view typeClass() const final { return "stream"; }

    bool isAllocable() const final { return true; }
    bool isMutable() const final { return true; }
    bool isSortable() const final { return true; }

    QualifiedType* elementType() const final { return iteratorType()->type()->dereferencedType(); }
    QualifiedType* iteratorType() const final { return viewType()->type()->iteratorType(); }
    QualifiedType* viewType() const final { return child<QualifiedType>(0); }

    static auto create(ASTContext* ctx, const Meta& meta = {}) {
        return ctx->make<Stream>(ctx, {QualifiedType::create(ctx, stream::View::create(ctx, meta), Constness::Mutable)},
                                 meta);
    }

protected:
    Stream(ASTContext* ctx, Nodes children, Meta meta)
        : UnqualifiedType(ctx, NodeTags, {"stream"}, std::move(children), std::move(meta)) {}

    void newlyQualified(const QualifiedType* qtype) const final { elementType()->setConst(qtype->constness()); }

    HILTI_NODE_1(type::Stream, UnqualifiedType, final);
};

} // namespace hilti::type
