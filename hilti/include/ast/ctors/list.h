// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/ctor.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/types/list.h>
#include <hilti/ast/types/unknown.h>

#include <utility>

namespace hilti {
namespace ctor {

/** AST node for a List constructor. */
class List : public NodeBase, public hilti::trait::isCtor {
public:
    List(std::vector<Expression> e, Meta m = Meta()) : NodeBase(nodes(inferType(e, m), e), m) {}
    List(Type t, std::vector<Expression> e, Meta m = Meta())
        : NodeBase(nodes(std::move(t), std::move(e)), std::move(m)) {}

    auto elementType() const { return type::effectiveType(child<Type>(0)); }
    auto value() const { return childs<Expression>(1, -1); }

    bool operator==(const List& other) const {
        return elementType() == other.elementType() && value() == other.value();
    }

    /** Implements `Ctor` interface. */
    auto type() const { return type::List(elementType(), meta()); }
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

private:
    Type inferType(const std::vector<Expression>& e, const Meta& /* m */) {
        return e.size() ? e.front().type() : type::unknown;
    }
};

} // namespace ctor
} // namespace hilti
