// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>
#include <vector>

#include <hilti/ast/attribute.h>
#include <hilti/ast/declarations/expression.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/expressions/keyword.h>
#include <hilti/ast/function.h>
#include <hilti/ast/id.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/function.h>
#include <hilti/ast/types/integer.h>
#include <hilti/ast/types/unknown.h>

#include <spicy/ast/aliases.h>

namespace spicy::type {

namespace bitfield {

/** AST node for a bitfield element. */
class Bits : public hilti::NodeBase {
public:
    Bits() : NodeBase({ID("<no id>"), hilti::node::none}, Meta()) {}
    Bits(ID id, int lower, int upper, int field_width, std::optional<AttributeSet> attrs = {}, Meta m = Meta())
        : hilti::NodeBase(nodes(std::move(id),
                                hilti::expression::Keyword::createDollarDollarDeclaration(
                                    hilti::type::UnsignedInteger(field_width)),
                                hilti::type::auto_, std::move(attrs)),
                          std::move(m)),
          _lower(lower),
          _upper(upper),
          _field_width(field_width) {}

    const auto& id() const { return child<ID>(0); }
    auto lower() const { return _lower; }
    auto upper() const { return _upper; }
    auto fieldWidth() const { return _field_width; }
    auto attributes() const { return children()[3].tryAs<AttributeSet>(); }
    const Type& ddType() const { return children()[1].as<hilti::declaration::Expression>().expression().type(); }
    NodeRef ddRef() const { return NodeRef(children()[1]); }
    const auto& itemType() const { return child<Type>(2); }

    /** Implements the `Node` interface. */
    auto properties() const {
        return node::Properties{
            {"lower", _lower},
            {"upper", _upper},
            {"field_width", _field_width},
        };
    }

    void setAttributes(const AttributeSet& attrs) { children()[3] = attrs; }
    void setItemType(const Type& t) { children()[2] = t; }

    bool operator==(const Bits& other) const {
        return id() == other.id() && _lower == other._lower && _upper == other._upper &&
               _field_width == other._field_width && itemType() == other.itemType() &&
               attributes() == other.attributes();
    }

private:
    int _lower = 0;
    int _upper = 0;
    int _field_width = 0;
};

inline hilti::Node to_node(Bits f) { return hilti::Node(std::move(f)); }

} // namespace bitfield

/** AST node for a struct type. */
class Bitfield : public hilti::TypeBase {
public:
    Bitfield(int width, std::vector<bitfield::Bits> bits, const Meta& m = Meta())
        : TypeBase(nodes(type::UnsignedInteger(width, m), hilti::type::auto_, std::move(bits)), m), _width(width) {}
    Bitfield(Wildcard /*unused*/, Meta m = Meta())
        : TypeBase({hilti::type::unknown, hilti::type::unknown}, std::move(m)), _wildcard(true) {}

    int width() const { return _width; }
    auto bits() const { return children<bitfield::Bits>(2, -1); }
    hilti::optional_ref<const bitfield::Bits> bits(const ID& id) const;
    std::optional<int> bitsIndex(const ID& id) const;
    const Type& parseType() const { return child<Type>(0); }
    const Type& type() const { return child<Type>(1); }

    void addField(bitfield::Bits f) { addChild(std::move(f)); }
    void setType(const Type& t) { children()[1] = t; }

    bool operator==(const Bitfield& other) const { return width() == other.width() && bits() == other.bits(); }

    bool isEqual(const Type& other) const override { return node::isEqual(this, other); }
    bool _isResolved(ResolvedState* rstate) const override { return true; }
    std::vector<hilti::Node> typeParameters() const override { return hilti::util::slice(children(), 1); }
    bool isWildcard() const override { return _wildcard; }
    node::Properties properties() const override { return node::Properties{}; }

    bool _isAllocable() const override { return true; }
    bool _isMutable() const override { return true; }
    bool _isParameterized() const override { return true; }

    const std::type_info& typeid_() const override { return typeid(decltype(*this)); }

private:
    int _width = 0;
    bool _wildcard = false;
};

} // namespace spicy::type
