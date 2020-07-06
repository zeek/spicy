// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>
#include <vector>

#include <hilti/ast/builder/type.h>
#include <hilti/ast/ctor.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/types/unknown.h>
#include <hilti/ast/types/vector.h>

namespace hilti {
namespace ctor {

/** AST node for a vector constructor. */
class Vector : public NodeBase, public hilti::trait::isCtor {
public:
    Vector(const std::vector<Expression>& e, const Meta& m = Meta())
        : NodeBase(nodes(builder::typeOfExpressions(e), e), m) {}
    Vector(Type t, std::vector<Expression> e, Meta m = Meta())
        : NodeBase(nodes(std::move(t), std::move(e)), std::move(m)) {}

    auto elementType() const { return type::effectiveType(child<Type>(0)); }
    auto value() const { return childs<Expression>(1, -1); }

    bool operator==(const Vector& other) const {
        return elementType() == other.elementType() && value() == other.value();
    }

    /** Implements `Ctor` interface. */
    auto type() const { return type::Vector(elementType(), meta()); }
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
