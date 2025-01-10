// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/type.h>
#include <hilti/ast/types/unknown.h>

namespace hilti::type {

/** AST node for a `exception` type. */
class Exception : public UnqualifiedType {
public:
    auto baseType() const { return child<UnqualifiedType>(0); }

    std::string_view typeClass() const final { return "exception"; }

    bool isAllocable() const final { return true; }
    bool isNameType() const final { return true; }

    static auto create(ASTContext* ctx, UnqualifiedType* base, Meta meta = {}) {
        return ctx->make<Exception>(ctx, {base}, std::move(meta));
    }

    static auto create(ASTContext* ctx, Meta meta = {}) { return create(ctx, nullptr, std::move(meta)); }

    static auto create(ASTContext* ctx, Wildcard _, const Meta& m = Meta()) {
        return ctx->make<Exception>(ctx, Wildcard(), {type::Unknown::create(ctx, m)}, m);
    }

protected:
    Exception(ASTContext* ctx, Nodes children, Meta meta)
        : UnqualifiedType(ctx, NodeTags, {}, std::move(children), std::move(meta)) {}
    Exception(ASTContext* ctx, Wildcard _, const Nodes& children, Meta meta)
        : UnqualifiedType(ctx, NodeTags, Wildcard(), {"exception(*)"}, children, std::move(meta)) {}

    bool isResolved(node::CycleDetector* cd) const final { return baseType() ? baseType()->isResolved(cd) : true; }

    HILTI_NODE_1(type::Exception, UnqualifiedType, final);
};

} // namespace hilti::type
