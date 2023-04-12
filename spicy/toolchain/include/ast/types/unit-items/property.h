// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/attribute.h>

#include <spicy/ast/aliases.h>
#include <spicy/ast/types/unit-item.h>
#include <spicy/ast/types/unit.h>

namespace spicy::type::unit::item {

/** AST node for a unit property. */
class Property : public hilti::NodeBase, public spicy::trait::isUnitItem {
public:
    Property(ID id, std::optional<AttributeSet> attrs = {}, bool inherited = false, Meta m = Meta())
        : NodeBase(nodes(std::move(id), node::none, std::move(attrs)), std::move(m)), _inherited(inherited) {}

    Property(ID id, Expression expr, std::optional<AttributeSet> attrs = {}, bool inherited = false, Meta m = Meta())
        : NodeBase(nodes(std::move(id), std::move(expr), std::move(attrs)), std::move(m)), _inherited(inherited) {}

    const auto& id() const { return child<ID>(0); }
    auto expression() const { return children()[1].tryAs<Expression>(); }
    auto attributes() const { return children()[2].tryAs<AttributeSet>(); }
    bool inherited() const { return _inherited; }

    bool operator==(const Property& other) const {
        return id() == other.id() && expression() == other.expression() && attributes() == other.attributes();
    }

    // Unit field interface
    const Type& itemType() const { return type::void_; }
    bool isResolved() const { return type::isResolved(itemType()); }
    auto isEqual(const Item& other) const { return node::isEqual(this, other); }

    // Node interface.
    auto properties() const { return node::Properties{{"inherited", _inherited}}; }

private:
    bool _inherited;
};

} // namespace spicy::type::unit::item
