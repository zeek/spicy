// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <algorithm>
#include <utility>
#include <vector>

#include <hilti/ast/ctor.h>
#include <hilti/ast/ctors/struct.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/id.h>
#include <hilti/ast/types/auto.h>
#include <hilti/ast/types/struct.h>

#include <spicy/ast/types/unit.h>

namespace spicy::ctor {

namespace unit {
/** AST node for a unit field constructor. */
using Field = hilti::ctor::struct_::Field;
} // namespace unit

/** AST node for a unit conunitor. */
class Unit : public hilti::NodeBase, public hilti::trait::isCtor {
public:
    Unit(std::vector<unit::Field> f, Meta m = Meta())
        : hilti::NodeBase(nodes(type::auto_, std::move(f)), std::move(m)) {}
    Unit(std::vector<unit::Field> f, Type t, Meta m = Meta())
        : NodeBase(nodes(std::move(t), std::move(f)), std::move(m)) {}

    /** Returns all fields that the constructor initializes. */
    auto fields() const { return children<unit::Field>(1, -1); }

    /*** Returns the unit type the constructor is producing. */
    auto utype() const { return child<type::Unit>(0); }

    /** Returns a field initialized by the constructor through its ID. */
    hilti::optional_ref<const unit::Field> field(const ID& id) const {
        for ( const auto& f : fields() ) {
            if ( f.id() == id )
                return f;
        }

        return {};
    }

    void setType(const Type& x) { children()[0] = x; }

    bool operator==(const Unit& other) const { return fields() == other.fields(); }

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

} // namespace spicy::ctor
