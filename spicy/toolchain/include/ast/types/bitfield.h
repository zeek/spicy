// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>
#include <vector>

#include <hilti/ast/attribute.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/function.h>
#include <hilti/ast/id.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/function.h>
#include <hilti/ast/types/integer.h>
#include <hilti/ast/types/unknown.h>

#include <spicy/ast/aliases.h>

namespace spicy {
namespace type {

namespace bitfield {

/** AST node for a bitfield element. */
class Bits : public hilti::NodeBase {
public:
    Bits() : NodeBase({ID("<no id>"), hilti::node::none}, Meta()) {}
    Bits(ID id, int lower, int upper, int field_width, std::optional<AttributeSet> attrs = {}, Meta m = Meta())
        : hilti::NodeBase(nodes(std::move(id), std::move(attrs)), std::move(m)),
          _lower(lower),
          _upper(upper),
          _field_width(field_width) {}

    const auto& id() const { return child<ID>(0); }
    auto lower() const { return _lower; }
    auto upper() const { return _upper; }
    Type type() const;
    auto attributes() const { return childs()[1].tryAs<AttributeSet>(); }

    /** Implements the `Node` interface. */
    auto properties() const {
        return node::Properties{
            {"lower", _lower},
            {"upper", _upper},
            {"field_width", _field_width},
        };
    }

    bool operator==(const Bits& other) const {
        return id() == other.id() && _lower == other._lower && _upper == other._upper &&
               _field_width == other._field_width && attributes() == other.attributes();
    }

    /**
     * Copies an existing bits instance but replaces its attributes.
     *
     * @param f original instance
     * @param attrs new attributes
     * @return new instances with attributes replaced
     */
    static Bits setAttributes(const Bits& f, const AttributeSet& attrs) {
        auto x = Bits(f);
        x.childs()[1] = attrs;
        return x;
    }

private:
    int _lower{0};
    int _upper{0};
    int _field_width{0};
};

inline hilti::Node to_node(Bits f) { return hilti::Node(std::move(f)); }

} // namespace bitfield

/** AST node for a struct type. */
class Bitfield : public hilti::TypeBase,
                 hilti::type::trait::isAllocable,
                 hilti::type::trait::isParameterized,
                 hilti::type::trait::isMutable {
public:
    Bitfield(int width, std::vector<bitfield::Bits> bits, Meta m = Meta())
        : TypeBase(nodes(std::move(bits)), std::move(m)), _width(width) {}
    Bitfield(Wildcard /*unused*/, Meta m = Meta()) : TypeBase({}, std::move(m)), _wildcard(true) {}

    int width() const { return _width; }
    auto bits() const { return childsOfType<bitfield::Bits>(); }
    std::optional<bitfield::Bits> bits(const ID& id) const;
    std::optional<int> bitsIndex(const ID& id) const;
    Type type() const;

    bool operator==(const Bitfield& other) const { return width() == other.width() && bits() == other.bits(); }

    /** For internal use by the builder API only. */
    auto _bitsNodes() { return nodesOfType<bitfield::Bits>(); }

    /** Implements the `Type` interface. */
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }
    /** Implements the `Type` interface. */
    auto typeParameters() const { return hilti::util::slice(childs(), 1); }
    /** Implements the `Type` interface. */
    auto isWildcard() const { return _wildcard; }
    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }

    /**
     * Copies an existing type and adds a new field to the copy.
     *
     * @param s original type
     * @param f field to add
     * @return new typed with field added
     */
    static Bitfield addField(const Bitfield& s, bitfield::Bits f) {
        auto x = Type(s)._clone().as<Bitfield>();
        x.addChild(std::move(f));
        return x;
    }

private:
    int _width = 0;
    bool _wildcard = false;
};

} // namespace type
} // namespace spicy
