// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <spicy/ast/aliases.h>
#include <spicy/ast/engine.h>
#include <spicy/ast/types/unit-item.h>
#include <spicy/ast/types/unit.h>

namespace spicy::type::unit::item {

/**
 * AST node for a unit variable.
 *
 * @note We don't support hooks for variables because we can't reliably
 * identify assignments in the generated code. To do that, we'd need to trap
 * struct field assignments at the C++ level.
 */
class Variable : public hilti::NodeBase, public spicy::trait::isUnitItem {
public:
    Variable(ID id, Type type, const std::optional<Expression>& default_, std::optional<AttributeSet> attrs = {},
             Meta m = Meta())
        : NodeBase(nodes(std::move(id), std::move(type), default_, std::move(attrs)), std::move(m)) {}

    const auto& id() const { return child<ID>(0); }
    auto default_() const { return children()[2].tryAs<Expression>(); }
    auto attributes() const { return children()[3].tryAs<AttributeSet>(); }

    bool isOptional() const { return AttributeSet::find(attributes(), "&optional").has_value(); }

    bool operator==(const Variable& other) const {
        return id() == other.id() && itemType() == other.itemType() && default_() == other.default_() &&
               attributes() == other.attributes();
    }

    // Unit item interface
    const Type& itemType() const { return child<Type>(1); }
    bool isResolved() const { return type::isResolved(itemType()); }
    auto isEqual(const Item& other) const { return node::isEqual(this, other); }

    // Node interface.
    auto properties() const { return node::Properties{}; }
};

} // namespace spicy::type::unit::item
