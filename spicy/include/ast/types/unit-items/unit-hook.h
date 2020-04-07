// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <spicy/ast/aliases.h>
#include <spicy/ast/types/unit-item.h>
#include <spicy/ast/types/unit.h>

namespace spicy::type::unit::item {

/** AST node for a unit hook. */
class UnitHook : public hilti::NodeBase, public spicy::trait::isUnitItem {
public:
    UnitHook(ID id, Hook hook, Meta m = Meta()) : NodeBase(nodes(std::move(id), std::move(hook)), std::move(m)) {}

    auto id() const { return child<ID>(0); }
    auto hook() const { return child<Hook>(1); }

    bool operator==(const UnitHook& other) const { return id() == other.id() && hook() == other.hook(); }

    // Unit field interface
    Type itemType() const { return hook().type(); }
    auto isEqual(const Item& other) const { return node::isEqual(this, other); }

    // Node interface.
    auto properties() const { return node::Properties{}; }
};

} // namespace spicy::type::unit::item
