// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/type.h>

namespace hilti::type {

/** AST node for an `any` type. */
class Any : public UnqualifiedType {
public:
    static auto create(ASTContext* ctx, Meta m = Meta()) { return std::shared_ptr<Any>(new Any(ctx, std::move(m))); }

    std::string_view typeClass() const final { return "any"; }

    bool isAllocable() const override { return true; }
    bool isSortable() const override { return true; }

protected:
    // We create this as no-match type because we handle matching against `any` explicitly.
    Any(ASTContext* ctx, Meta meta) : UnqualifiedType(ctx, NodeTags, {type::NeverMatch()}, std::move(meta)) {}

    HILTI_NODE_1(type::Any, UnqualifiedType, final);
};

} // namespace hilti::type
