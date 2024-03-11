// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>
#include <vector>

#include <hilti/ast/type.h>
#include <hilti/ast/types/unknown.h>

namespace hilti::type {

/** AST node for an `optional<T>` type. */
class Optional : public UnqualifiedType {
public:
    QualifiedType* dereferencedType() const final { return child(0)->as<QualifiedType>(); }

    std::string_view typeClass() const final { return "optional"; }

    bool isAllocable() const final { return true; }
    bool isResolved(node::CycleDetector* cd) const final { return dereferencedType()->isResolved(cd); }

    static auto create(ASTContext* ctx, QualifiedType* t, Meta m = Meta()) {
        return ctx->make<Optional>(ctx, {t}, std::move(m));
    }

    static auto create(ASTContext* ctx, Wildcard _, const Meta& m = Meta()) {
        return ctx->make<Optional>(ctx, Wildcard(),
                                   {QualifiedType::create(ctx, type::Unknown::create(ctx, m), Constness::Const)}, m);
    }

protected:
    Optional(ASTContext* ctx, Nodes children, Meta meta)
        : UnqualifiedType(ctx, NodeTags, {}, std::move(children), std::move(meta)) {}
    Optional(ASTContext* ctx, Wildcard _, Nodes children, Meta meta)
        : UnqualifiedType(ctx, NodeTags, Wildcard(), {"optional(*)"}, std::move(children), std::move(meta)) {}


    HILTI_NODE_1(type::Optional, UnqualifiedType, final);
};


} // namespace hilti::type
