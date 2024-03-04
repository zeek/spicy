// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>
#include <utility>

#include <hilti/ast/attribute.h>
#include <hilti/ast/type.h>

#include <spicy/ast/declarations/hook.h>
#include <spicy/ast/types/unit-item.h>

namespace spicy::type::unit::item {

/**
 * AST node for a unit hook.
 */
class UnitHook : public unit::Item {
public:
    auto hook() const { return child<spicy::declaration::Hook>(0); }
    auto location() const { return hook()->location(); }

    QualifiedTypePtr itemType() const final { return hook()->function()->type(); }

    bool isResolved(hilti::node::CycleDetector* cd) const final { return itemType()->isResolved(cd); }

    std::string_view displayName() const final { return "unit hook"; }

    static auto create(ASTContext* ctx, const ID& id, spicy::declaration::HookPtr hook, const Meta& meta = {}) {
        auto h = std::shared_ptr<UnitHook>(new UnitHook(ctx, {std::move(hook)}, id, meta));
        h->hook()->setID(id);
        return h;
    }

protected:
    UnitHook(ASTContext* ctx, Nodes children, ID id, const Meta& meta)
        : unit::Item(ctx, NodeTags, std::move(children), std::move(id), meta) {}

    SPICY_NODE_2(type::unit::item::UnitHook, type::unit::Item, Declaration, final);
};

} // namespace spicy::type::unit::item
