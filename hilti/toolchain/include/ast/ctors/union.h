// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/ctor.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/id.h>
#include <hilti/ast/types/struct.h>

namespace hilti::ctor {

/** AST node for a struct constructor. */
class Union : public NodeBase, public hilti::trait::isCtor {
public:
    Union(Type unit_type, Expression value, Meta m = Meta())
        : NodeBase(nodes(std::move(unit_type), std::move(value)), std::move(m)) {}

    /** Returns the value to initialize the unit with. */
    const Expression& value() const { return child<Expression>(1); }

    bool operator==(const Union& other) const { return type() == other.type() && value() == other.value(); }

    /** Implements `Ctor` interface. */
    const Type& type() const { return child<Type>(0); }

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
