// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/type.h>

#include <spicy/ast/forward.h>
#include <spicy/ast/node.h>

namespace spicy::type {

/** AST node for a Sink type. */
class Sink : public UnqualifiedType {
public:
    static auto create(ASTContext* ctx, Meta meta = {}) { return ctx->make<Sink>(ctx, std::move(meta)); }

    std::string_view typeClass() const final { return "sink"; }

    bool isAllocable() const final { return true; }

protected:
    Sink(ASTContext* ctx, Meta meta) : UnqualifiedType(ctx, NodeTags, {"sink"}, std::move(meta)) {}

    SPICY_NODE_1(type::Sink, UnqualifiedType, final);
};

} // namespace spicy::type
