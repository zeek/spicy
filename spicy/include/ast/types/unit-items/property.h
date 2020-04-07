// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <spicy/ast/aliases.h>
#include <spicy/ast/types/unit-item.h>
#include <spicy/ast/types/unit.h>

namespace spicy::type::unit::item {

/** AST node for a unit property. */
class Property : public hilti::NodeBase, public spicy::trait::isUnitItem {
public:
    Property(ID id, bool inherited = false, Meta m = Meta())
        : NodeBase(nodes(std::move(id), node::none), std::move(m)), _inherited(inherited) {}

    Property(ID id, Expression attr, bool inherited = false, Meta m = Meta())
        : NodeBase(nodes(std::move(id), std::move(attr)), std::move(m)), _inherited(inherited) {}

    auto id() const { return child<ID>(0); }
    auto expression() const { return childs()[1].tryAs<Expression>(); }
    bool interited() const { return _inherited; }

    bool operator==(const Property& other) const { return id() == other.id() && expression() == other.expression(); }

    // Unit field interface
    Type itemType() const { return type::Void(); }
    auto isEqual(const Item& other) const { return node::isEqual(this, other); }

    // Node interface.
    auto properties() const { return node::Properties{{"inherited", _inherited}}; }

private:
    bool _inherited;
};

} // namespace spicy::type::unit::item
