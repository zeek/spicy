// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/type.h>

namespace hilti::type {

/** AST node for a `interval` type. */
class Interval : public UnqualifiedType {
public:
    std::string_view typeClass() const final { return "interval"; }

    bool isAllocable() const final { return true; }
    bool isSortable() const final { return true; }

    static auto create(ASTContext* ctx, Meta meta = {}) { return ctx->make<Interval>(ctx, std::move(meta)); }

protected:
    Interval(ASTContext* ctx, Meta meta) : UnqualifiedType(ctx, NodeTags, {"interval"}, std::move(meta)) {}

    HILTI_NODE_1(type::Interval, UnqualifiedType, final);
};

} // namespace hilti::type
