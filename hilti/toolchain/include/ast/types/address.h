// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/type.h>

namespace hilti::type {

/** AST node for an `addr` type. */
class Address : public UnqualifiedType {
public:
    static auto create(ASTContext* ctx, const Meta& m = Meta()) { return ctx->make<Address>(ctx, m); }

    std::string_view typeClass() const final { return "address"; }

    bool isAllocable() const final { return true; }
    bool isSortable() const final { return true; }

protected:
    Address(ASTContext* ctx, Meta meta) : UnqualifiedType(ctx, NodeTags, {"address"}, std::move(meta)) {}

    HILTI_NODE_1(type::Address, UnqualifiedType, final);
};

} // namespace hilti::type
