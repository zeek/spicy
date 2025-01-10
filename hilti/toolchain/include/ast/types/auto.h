// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/type.h>

namespace hilti::type {

/** AST node for an `auto` type. */
class Auto : public UnqualifiedType {
public:
    static auto create(ASTContext* ctx, const Meta& m = Meta()) { return ctx->make<Auto>(ctx, m); }

    std::string_view typeClass() const final { return "auto"; }

    bool isResolved(node::CycleDetector* cd) const final { return false; }

protected:
    Auto(ASTContext* ctx, Meta meta) : UnqualifiedType(ctx, NodeTags, {}, std::move(meta)) {}


    HILTI_NODE_1(type::Auto, UnqualifiedType, final);
};

} // namespace hilti::type
