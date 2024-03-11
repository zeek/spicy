// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/type.h>

namespace hilti::type {

/** AST node for a `time` type. */
class Time : public UnqualifiedType {
public:
    std::string_view typeClass() const final { return "time"; }

    bool isAllocable() const final { return true; }
    bool isSortable() const final { return true; }

    static auto create(ASTContext* ctx, Meta meta = {}) { return ctx->make<Time>(ctx, std::move(meta)); }

protected:
    Time(ASTContext* ctx, Meta meta) : UnqualifiedType(ctx, NodeTags, {"time"}, std::move(meta)) {}

    HILTI_NODE_1(type::Time, UnqualifiedType, final);
};

} // namespace hilti::type
