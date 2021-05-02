// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>
#include <vector>

#include <hilti/ast/builder/type.h>
#include <hilti/ast/ctor.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/types/auto.h>
#include <hilti/ast/types/bool.h>
#include <hilti/ast/types/set.h>

namespace hilti {
namespace ctor {

/** AST node for a set constructor. */
class Set : public NodeBase, public hilti::trait::isCtor {
public:
    Set(std::vector<Expression> e, Meta m = Meta())
        : NodeBase(nodes(type::Set(e.size() ? Type(type::auto_) : Type(type::Bool())), e), m) {
    } // Bool is just an arbitrary place-holder type for empty values
    Set(Type t, std::vector<Expression> e, Meta m = Meta()) : NodeBase(nodes(type::Set(t, m), std::move(e)), m) {}

    const auto& elementType() const { return childs()[0].as<type::Set>().elementType(); }
    auto value() const { return childs<Expression>(1, -1); }

    void setElementType(Type t) { childs()[0] = type::Set(std::move(t), meta()); }

    void setValue(std::vector<Expression> elems) {
        childs().erase(childs().begin() + 1, childs().end());
        for ( auto&& e : elems )
            childs().push_back(e);
    }

    bool operator==(const Set& other) const { return elementType() == other.elementType() && value() == other.value(); }

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
