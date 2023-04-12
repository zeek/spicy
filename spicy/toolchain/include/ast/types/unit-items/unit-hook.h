// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <spicy/ast/aliases.h>
#include <spicy/ast/types/unit-item.h>
#include <spicy/ast/types/unit.h>

namespace spicy::type::unit::item {

/** AST node for a unit hook. */
class UnitHook : public hilti::NodeBase, public spicy::trait::isUnitItem {
public:
    UnitHook(const ID& id, Hook hook, Meta m = Meta()) : NodeBase(nodes(id, std::move(hook)), std::move(m)) {
        children()[1].as<Hook>().setID(id);
    }

    const auto& id() const { return child<ID>(0); }
    const auto& hook() const { return child<Hook>(1); }
    const auto& location() const { return children()[0].location(); }

    bool operator==(const UnitHook& other) const { return id() == other.id() && hook() == other.hook(); }

    // Unit field interface
    const Type& itemType() const { return hook().function().type(); }
    bool isResolved() const { return type::isResolved(itemType()); }
    auto isEqual(const Item& other) const { return node::isEqual(this, other); }

    // Node interface.
    auto properties() const { return node::Properties{}; }
};

} // namespace spicy::type::unit::item
