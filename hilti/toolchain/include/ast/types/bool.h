// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/type.h>

namespace hilti::type {

/** AST node for a `bool` type. */
class Bool : public UnqualifiedType {
public:
    static auto create(ASTContext* ctx, Meta meta = {}) { return ctx->make<Bool>(ctx, std::move(meta)); }

    std::string_view typeClass() const final { return "bool"; }

    bool isAllocable() const final { return true; }
    bool isSortable() const final { return true; }

protected:
    Bool(ASTContext* ctx, Meta meta) : UnqualifiedType(ctx, NodeTags, {"bool"}, std::move(meta)) {}

    HILTI_NODE_1(type::Bool, UnqualifiedType, final);
};

} // namespace hilti::type
