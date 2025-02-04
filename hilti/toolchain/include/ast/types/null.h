// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/type.h>

namespace hilti::type {

/** * AST node for a null type. */
class Null : public UnqualifiedType {
public:
    std::string_view typeClass() const final { return "null"; }

    static auto create(ASTContext* ctx, Meta meta = {}) { return ctx->make<Null>(ctx, std::move(meta)); }

protected:
    Null(ASTContext* ctx, Meta meta) : UnqualifiedType(ctx, NodeTags, {"null"}, std::move(meta)) {}

    HILTI_NODE_1(type::Null, UnqualifiedType, final);
};

} // namespace hilti::type
