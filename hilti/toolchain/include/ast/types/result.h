// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>
#include <vector>

#include <hilti/ast/type.h>
#include <hilti/ast/types/unknown.h>

namespace hilti::type {

/** AST node for an `result<T>` type. */
class Result : public UnqualifiedType {
public:
    std::string_view typeClass() const final { return "result"; }

    QualifiedType* dereferencedType() const final { return child(0)->as<QualifiedType>(); }

    bool isAllocable() const final { return true; }
    bool isResolved(node::CycleDetector* cd) const final { return dereferencedType()->isResolved(cd); }

    static auto create(ASTContext* ctx, QualifiedType* t, Meta m = Meta()) {
        return ctx->make<Result>(ctx, {t}, std::move(m));
    }

    static auto create(ASTContext* ctx, Wildcard _, const Meta& m = Meta()) {
        return ctx->make<Result>(ctx, Wildcard(),
                                 {QualifiedType::create(ctx, type::Unknown::create(ctx, m), Constness::Const)}, m);
    }

protected:
    Result(ASTContext* ctx, Nodes children, Meta meta)
        : UnqualifiedType(ctx, NodeTags, {}, std::move(children), std::move(meta)) {}
    Result(ASTContext* ctx, Wildcard _, Nodes children, Meta meta)
        : UnqualifiedType(ctx, NodeTags, Wildcard(), {"result(*)"}, std::move(children), std::move(meta)) {}


    HILTI_NODE_1(type::Result, UnqualifiedType, final);
};

} // namespace hilti::type
