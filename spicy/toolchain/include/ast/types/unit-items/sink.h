// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>
#include <utility>

#include <hilti/ast/attribute.h>
#include <hilti/ast/type.h>

#include <spicy/ast/types/sink.h>
#include <spicy/ast/types/unit-item.h>

namespace spicy::type::unit::item {

/**
 * AST node for a unit sink.
 */
class Sink : public unit::Item {
public:
    auto attributes() const { return child<AttributeSet>(0); }

    QualifiedType* itemType() const final { return child<QualifiedType>(1); }

    bool isResolved(hilti::node::CycleDetector* cd) const final { return itemType()->isResolved(cd); }

    std::string_view displayName() const final { return "unit sink"; }

    static auto create(ASTContext* ctx, ID id, AttributeSet* attrs, Meta meta = {}) {
        if ( ! attrs )
            attrs = AttributeSet::create(ctx);

        return ctx->make<Sink>(ctx,
                               {attrs, QualifiedType::create(ctx, type::Sink::create(ctx), hilti::Constness::Mutable)},
                               std::move(id), std::move(meta));
    }

protected:
    Sink(ASTContext* ctx, Nodes children, ID id, Meta meta)
        : unit::Item(ctx, NodeTags, std::move(children), std::move(id), std::move(meta)) {}

    SPICY_NODE_2(type::unit::item::Sink, type::unit::Item, Declaration, final);
};

} // namespace spicy::type::unit::item
