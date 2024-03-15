// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/type.h>
#include <hilti/ast/types/unknown.h>

namespace hilti::type {

/** AST node for a type representing a type value. */
class Type_ : public UnqualifiedType {
public:
    auto typeValue() const { return child<QualifiedType>(0); }

    std::string_view typeClass() const final { return "type"; }

    bool isResolved(node::CycleDetector* cd) const final { return typeValue()->isResolved(cd); }

    static auto create(ASTContext* ctx, QualifiedType* type, Meta meta = {}) {
        return ctx->make<Type_>(ctx, {type}, std::move(meta));
    }

    static auto create(ASTContext* ctx, Wildcard _, const Meta& m = Meta()) {
        return ctx->make<Type_>(ctx, Wildcard(),
                                {QualifiedType::create(ctx, type::Unknown::create(ctx, m), Constness::Const)}, m);
    }

protected:
    Type_(ASTContext* ctx, Nodes children, Meta meta)
        : UnqualifiedType(ctx, NodeTags, {}, std::move(children), std::move(meta)) {}
    Type_(ASTContext* ctx, Wildcard _, Nodes children, Meta meta)
        : UnqualifiedType(ctx, NodeTags, Wildcard(), {"type(*)"}, std::move(children), std::move(meta)) {}


    HILTI_NODE_1(type::Type_, UnqualifiedType, final);
};

} // namespace hilti::type
