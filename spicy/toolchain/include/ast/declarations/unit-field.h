// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <utility>
#include <vector>

#include <hilti/ast/declaration.h>
#include <hilti/ast/types/reference.h>
#include <hilti/ast/types/struct.h>

#include <spicy/ast/types/unit-items/unresolved-field.h>

namespace spicy {
namespace declaration {

/**
 * AST node for an external alias of a unit field's type, which can then be
 * pulled into an actual unit.
 */
class UnitField : public hilti::NodeBase, public hilti::trait::isDeclaration {
public:
    UnitField(ID id, Type type, std::optional<Expression> repeat,
              std::optional<AttributeSet> attrs, std::vector<Hook> hooks = {}, Meta m = Meta())

        : NodeBase(nodes(std::move(id), std::move(type), std::move(repeat), std::move(attrs), std::move(hooks)), std::move(m)) {}

    UnitField(ID id, Ctor ctor, std::optional<Expression> repeat,
              std::optional<AttributeSet> attrs, std::vector<Hook> hooks = {}, Meta m = Meta())

        : NodeBase(nodes(std::move(id), std::move(ctor), std::move(repeat), std::move(attrs), std::move(hooks)), std::move(m)) {}

    UnitField(ID id, type::unit::Item item, std::optional<Expression> repeat,
              std::optional<AttributeSet> attrs, std::vector<Hook> hooks = {}, Meta m = Meta())

        : NodeBase(nodes(std::move(id), std::move(item), std::move(repeat), std::move(attrs), std::move(hooks)), std::move(m)) {}

    UnitField(ID id, ID unresolved_id, std::optional<Expression> repeat,
              std::optional<AttributeSet> attrs, std::vector<Hook> hooks = {}, Meta m = Meta())

        : NodeBase(nodes(std::move(id), std::move(unresolved_id), std::move(repeat), std::move(attrs), std::move(hooks)),
                   std::move(m)) {}

    // Only one of these will have a return value.
    auto unresolvedID() const { return childs()[1].tryAs<ID>(); }
    auto type() const { return childs()[1].tryAs<Type>(); }
    auto ctor() const { return childs()[1].tryAs<Ctor>(); }
    auto item() const { return childs()[1].tryAs<type::unit::Item>(); }

    auto repeatCount() const { return childs()[2].tryAs<Expression>(); }
    auto attributes() const { return childs()[3].tryAs<AttributeSet>(); }
    auto hooks() const { return childs<Hook>(4, -1); }

    bool operator==(const UnitField& other) const {
        return id() == other.id() && unresolvedID() == other.unresolvedID() && type() == other.type() &&
               ctor() == other.ctor() && /* item() == other.item() && */ repeatCount() == other.repeatCount() &&
               attributes() == other.attributes() && hooks() == other.hooks();
    }

    /** Implements `Declaration` interface. */
    bool isConstant() const { return true; }
    /** Implements `Declaration` interface. */
    ID id() const { return child<ID>(0); }
    /** Implements `Declaration` interface. */
    Linkage linkage() const { return _linkage; }
    /** Implements `Declaration` interface. */
    std::string displayName() const { return "unit field"; };
    /** Implements `Declaration` interface. */
    auto isEqual(const Declaration& other) const { return node::isEqual(this, other); }

    /** Implements `Node` interface. */
    auto properties() const { return node::Properties{{"linkage", to_string(_linkage)}}; }

private:
    Linkage _linkage;
};

} // namespace declaration
} // namespace spicy
