// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>
#include <vector>

#include <hilti/ast/builder/type.h>
#include <hilti/ast/ctor.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/types/auto.h>
#include <hilti/ast/types/bool.h>
#include <hilti/ast/types/vector.h>

namespace hilti {
namespace ctor {

/** AST node for a vector constructor. */
class Vector : public NodeBase, public hilti::trait::isCtor {
public:
    Vector(std::vector<Expression> e, Meta m = Meta())
        : NodeBase(nodes(type::Vector(e.size() ? Type(type::auto_) : Type(type::Bool())), e), m) {
    } // Bool is just an arbitrary place-holder type for empty values
    Vector(Type t, std::vector<Expression> e, Meta m = Meta()) : NodeBase(nodes(type::Vector(t, m), std::move(e)), m) {}

    const auto& elementType() const { return childs()[0].as<type::Vector>().elementType(); }
    auto value() const { return childs<Expression>(1, -1); }

    void setElementType(Type t) { childs()[0] = type::Vector(std::move(t), meta()); }

    void setValue(std::vector<Expression> elems) {
        childs().erase(childs().begin() + 1, childs().end());
        for ( auto&& e : elems )
            childs().push_back(e);
    }

    bool operator==(const Vector& other) const {
        return elementType() == other.elementType() && value() == other.value();
    }

    /** Implements `Ctor` interface. */
    const auto& type() const { return child<Type>(0); }
    /** Implements `Ctor` interface. */
    bool isConstant() const { return false; }
    /** Implements `Ctor` interface. */
    auto isLhs() const { return false; }
    /** Implements `Ctor` interface. */
    auto isTemporary() const { return true; }
    /** Implements `Ctor` interface. */
    auto isEqual(const Ctor& other) const { return node::isEqual(this, other); }
    /** Implements `Node` interface. */
    auto properties() const { return node::Properties{}; }
};

} // namespace ctor
} // namespace hilti
