// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <algorithm>
#include <utility>
#include <vector>

#include <hilti/ast/builder/type.h>
#include <hilti/ast/ctor.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/types/auto.h>
#include <hilti/ast/types/bool.h>
#include <hilti/ast/types/map.h>

namespace hilti::ctor {

namespace map {
/** AST node for a map element constructor. */
class Element : public NodeBase {
public:
    Element(Expression k, Expression v, Meta m = Meta()) : NodeBase(nodes(std::move(k), std::move(v)), std::move(m)) {}
    Element(Meta m = Meta()) : NodeBase(nodes(node::none, node::none), std::move(m)) {}

    const auto& key() const { return child<Expression>(0); }
    const auto& value() const { return child<Expression>(1); }

    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }

    bool operator==(const Element& other) const { return key() == other.key() && value() == other.value(); }
};

inline Node to_node(Element f) { return Node(std::move(f)); }
} // namespace map

/** AST node for a map constructor. */
class Map : public NodeBase, public hilti::trait::isCtor {
public:
    Map(const std::vector<map::Element>& e, const Meta& m = Meta())
        : NodeBase(nodes(e.size() ? Type(type::auto_) : Type(type::Bool()), e), m) {}
    Map(const Type& key, const Type& value, const std::vector<map::Element>& e, const Meta& m = Meta())
        : NodeBase(nodes(type::Map(key, value, m), e), m) {}

    const auto& keyType() const {
        if ( auto t = children()[0].tryAs<type::Map>() )
            return t->keyType();
        else
            return children()[0].as<Type>();
    }

    const auto& valueType() const {
        if ( auto t = children()[0].tryAs<type::Map>() )
            return t->valueType();
        else
            return children()[0].as<Type>();
    }

    auto value() const { return children<map::Element>(1, -1); }

    void setElementType(const Type& k, const Type& v) { children()[0] = type::Map(k, v, meta()); }

    void setValue(const std::vector<map::Element>& elems) {
        children().erase(children().begin() + 1, children().end());
        for ( auto&& e : elems )
            children().emplace_back(e);
    }

    bool operator==(const Map& other) const {
        return keyType() == other.keyType() && valueType() == other.valueType() && value() == other.value();
    }

    /** Implements `Ctor` interface. */
    const auto& type() const { return children()[0].as<Type>(); }
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

} // namespace hilti::ctor
