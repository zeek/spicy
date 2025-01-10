// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/type.h>

namespace hilti::type {

/** AST node for an unknown place-holder type. */
class Unknown : public UnqualifiedType {
public:
    std::string_view typeClass() const final { return "unknown"; }

    static auto create(ASTContext* ctx, Meta meta = {}) { return ctx->make<Unknown>(ctx, std::move(meta)); }

protected:
    Unknown(ASTContext* ctx, Meta meta) : UnqualifiedType(ctx, NodeTags, {type::NeverMatch()}, std::move(meta)) {}

    HILTI_NODE_1(type::Unknown, UnqualifiedType, final);
};

} // namespace hilti::type
