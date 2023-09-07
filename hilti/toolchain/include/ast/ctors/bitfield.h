// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <algorithm>
#include <utility>
#include <vector>

#include <hilti/ast/ctor.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/id.h>
#include <hilti/ast/types/bitfield.h>

namespace hilti::ctor {

namespace bitfield {
/** AST node for a bitfield element value. */
class Bits : public NodeBase {
public:
    Bits(ID id, Expression e, Meta m = Meta()) : NodeBase(nodes(std::move(id), std::move(e)), std::move(m)) {}
    Bits(Meta m = Meta()) : NodeBase(nodes(node::none, node::none), std::move(m)) {}

    const auto& id() const { return child<ID>(0); }
    const auto& expression() const { return child<Expression>(1); }

    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }

    bool operator==(const Bits& other) const { return id() == other.id() && expression() == other.expression(); }
};

inline Node to_node(Bits f) { return Node(std::move(f)); }
} // namespace bitfield

/** AST node for a bitfield constructor. */
class Bitfield : public NodeBase, public hilti::trait::isCtor {
public:
    Bitfield(std::vector<bitfield::Bits> bits, type::Bitfield type, Meta m = Meta())
        : NodeBase(nodes(std::move(type), std::move(bits)), std::move(m)) {}

    /** Returns all bits that the constructors initializes. */
    auto bits() const { return children<bitfield::Bits>(1, -1); }

    /** Returns the underlying bitfield type. */
    const auto& btype() const { return child<type::Bitfield>(0); }

    /** Returns a field initialized by the constructor by its ID. */
    hilti::optional_ref<const bitfield::Bits> bits(const ID& id) const {
        for ( const auto& b : bits() ) {
            if ( b.id() == id )
                return b;
        }

        return {};
    }

    bool operator==(const Bitfield& other) const { return bits() == other.bits() && btype() == other.btype(); }

    /** Implements `Ctor` interface. */
    const auto& type() const { return child<Type>(0); }

    /** Implements `Ctor` interface. */
    bool isConstant() const { return true; }
    /** Implements `Ctor` interface. */
    auto isLhs() const { return false; }
    /** Implements `Ctor` interface. */
    auto isTemporary() const { return true; }
    /** Implements `Ctor` interface. */
    auto isEqual(const Ctor& other) const { return node::isEqual(this, other); }

    /** Implements `Node` interface. */
    auto properties() const { return node::Properties{}; }
};

} // namespace hilti::ctor
