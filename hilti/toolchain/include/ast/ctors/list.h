// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>
#include <vector>

#include <hilti/ast/builder/type.h>
#include <hilti/ast/ctor.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/types/auto.h>
#include <hilti/ast/types/bool.h>
#include <hilti/ast/types/list.h>

namespace hilti::ctor {

/** AST node for a List constructor. */
class List : public NodeBase, public hilti::trait::isCtor {
public:
    List(const std::vector<Expression>& e, Meta m = Meta())
        : NodeBase(nodes(type::List(e.size() ? Type(type::auto_) : Type(type::Bool())), e), std::move(m)) {
    } // Bool is just an arbitrary place-holder type for empty values
    List(const Type& t, std::vector<Expression> e, const Meta& m = Meta())
        : NodeBase(nodes(type::List(t, m), std::move(e)), m) {}

    const auto& elementType() const { return children()[0].as<type::List>().elementType(); }
    auto value() const { return children<Expression>(1, -1); }

    void setElementType(const Type& t) { children()[0] = type::List(t, meta()); }

    void setValue(const std::vector<Expression>& elems) {
        children().erase(children().begin() + 1, children().end());
        for ( auto&& e : elems )
            children().emplace_back(e);
    }

    bool operator==(const List& other) const {
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

} // namespace hilti::ctor
