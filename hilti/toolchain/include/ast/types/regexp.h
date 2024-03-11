// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/type.h>

namespace hilti::type {

/** AST node for a regular expression type. */
class RegExp : public UnqualifiedType {
public:
    std::string_view typeClass() const final { return "regexp"; }

    bool isAllocable() const final { return true; }
    bool isSortable() const final { return true; }

    static auto create(ASTContext* ctx, Meta meta = {}) { return ctx->make<RegExp>(ctx, std::move(meta)); }

protected:
    RegExp(ASTContext* ctx, Meta meta) : UnqualifiedType(ctx, NodeTags, {"regexp"}, std::move(meta)) {}

    HILTI_NODE_1(type::RegExp, UnqualifiedType, final);
};

} // namespace hilti::type
