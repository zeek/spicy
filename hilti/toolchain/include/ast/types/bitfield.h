// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

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

namespace hilti::type {

namespace bitfield {

/** AST node for a bitfield element. */
class Bits : public hilti::NodeBase {
public:
    Bits() : NodeBase({ID("<no id>"), hilti::node::none}, Meta()) {}

    Bits(ID id, int lower, int upper, int field_width, std::optional<AttributeSet> attrs = {}, Meta m = Meta())
        : hilti::NodeBase(nodes(std::move(id),
                                hilti::expression::Keyword::createDollarDollarDeclaration(
                                    hilti::type::UnsignedInteger(field_width)),
                                hilti::type::auto_, std::move(attrs), hilti::node::none),
                          std::move(m)),
          _lower(lower),
          _upper(upper),
          _field_width(field_width) {}

    Bits(ID id, int lower, int upper, int field_width, std::optional<AttributeSet> attrs = {},
         std::optional<Expression> ctor_value = {}, Meta m = Meta())
        : hilti::NodeBase(nodes(std::move(id),
                                hilti::expression::Keyword::createDollarDollarDeclaration(
                                    hilti::type::UnsignedInteger(field_width)),
                                hilti::type::auto_, std::move(attrs), std::move(ctor_value)),
                          std::move(m)),
          _lower(lower),
          _upper(upper),
          _field_width(field_width) {}

    const auto& id() const { return child<ID>(0); }
    auto lower() const { return _lower; }
    auto upper() const { return _upper; }
    auto fieldWidth() const { return _field_width; }
    auto attributes() const { return children()[3].tryAs<AttributeSet>(); }
    auto ctorValue() const { return children()[4].tryAs<Expression>(); }

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
    void setCtorValue(const Expression& e) { children()[4] = e; }

    bool operator==(const Bits& other) const {
        return id() == other.id() && _lower == other._lower && _upper == other._upper &&
               _field_width == other._field_width && itemType() == other.itemType() && ctorValue() == other.ctorValue();
        // TODO: Attributes don't quite compare correctly, see e.g., spicy.types.bitfield.parse-enum failure
        // && attributes() == other.attributes();
    }

private:
    int _lower = 0;
    int _upper = 0;
    int _field_width = 0;
};

inline hilti::Node to_node(Bits f) { return hilti::Node(std::move(f)); }

} // namespace bitfield

/** AST node for a struct type. */
class Bitfield : public hilti::TypeBase,
                 hilti::type::trait::isAllocable,
                 hilti::type::trait::isParameterized,
                 hilti::type::trait::isMutable {
public:
    Bitfield(int width, std::vector<bitfield::Bits> bits, std::optional<AttributeSet> attributes,
             const Meta& m = Meta())
        : TypeBase(nodes(type::UnsignedInteger(width, m), std::move(attributes), std::move(bits)), m), _width(width) {
        // Add a hidden range storing the original integer value.
        addChild(bitfield::Bits(ID("__value__"), 0, width - 1, width, {}, m));
    }

    Bitfield(Wildcard /*unused*/, Meta m = Meta())
        : TypeBase({hilti::type::unknown, hilti::type::unknown}, std::move(m)), _wildcard(true) {}

    int width() const { return _width; }
    auto bits(bool include_hidden = false) const { return children<bitfield::Bits>(2, include_hidden ? -1 : -2); }
    hilti::optional_ref<const bitfield::Bits> bits(const ID& id) const;
    std::optional<int> bitsIndex(const ID& id) const;
    auto attributes() const { return children()[1].tryAs<AttributeSet>(); }

    /**
     * If at least one of the bits comes with a pre-defined value, this builds
     * a bitfield ctor value that corresponds to all values defined by any of
     * the bits. If none does, return nothing.
     */
    std::optional<Ctor> ctorValue() const;

    bool operator==(const Bitfield& other) const { return width() == other.width() && bits() == other.bits(); }

    /** Implements the `Type` interface. */
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }
    /** Implements the `Type` interface. */
    auto _isResolved(ResolvedState* rstate) const {
        auto bs = bits();
        return std::all_of(bs.begin(), bs.end(),
                           [&](const auto& b) { return type::detail::isResolved(b.itemType(), rstate); });
    }

    void setAttributes(const AttributeSet& attrs) { children()[1] = attrs; }

    /** Implements the `Type` interface. */
    auto typeParameters() const { return hilti::util::slice(children(), 2); }
    /** Implements the `Type` interface. */
    auto isWildcard() const { return _wildcard; }
    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }

private:
    int _width = 0;
    bool _wildcard = false;
};

} // namespace hilti::type
