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

    QualifiedTypePtr itemType() const final { return child<QualifiedType>(1); }

    bool isResolved(hilti::node::CycleDetector* cd) const final { return itemType()->isResolved(cd); }

    std::string displayName() const final { return "unit sink"; }

    static auto create(ASTContext* ctx, ID id, AttributeSetPtr attrs, const Meta& meta = {}) {
        if ( ! attrs )
            attrs = AttributeSet::create(ctx);

        return std::shared_ptr<Sink>(
            new Sink(ctx, {attrs, QualifiedType::create(ctx, type::Sink::create(ctx), hilti::Constness::NonConst)},
                     std::move(id), meta));
    }

protected:
    Sink(ASTContext* ctx, Nodes children, ID id, const Meta& meta)
        : unit::Item(ctx, std::move(children), std::move(id), meta) {}

    HILTI_NODE(spicy, Sink)
};

} // namespace spicy::type::unit::item
