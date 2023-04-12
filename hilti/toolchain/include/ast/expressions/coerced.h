// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/expression.h>

namespace hilti::expression {

/** AST node for an expression that's being coerced from one type to another. */
class Coerced : public NodeBase, public trait::isExpression {
public:
    Coerced(Expression e, Type t, Meta m = Meta())
        : NodeBase({std::move(e), type::nonConstant(std::move(t))}, std::move(m)) {}

    const auto& expression() const { return child<Expression>(0); }

    bool operator==(const Coerced& other) const { return expression() == other.expression() && type() == other.type(); }

    /** Implements `Expression` interface. */
    bool isLhs() const { return expression().isLhs(); }
    /** Implements `Expression` interface. */
    bool isTemporary() const { return true; }
    /** Implements `Expression` interface. */
    const Type& type() const { return child<Type>(1); }
    /** Implements `Expression` interface. */
    auto isConstant() const { return expression().isConstant(); }
    /** Implements `Expression` interface. */
    auto isEqual(const Expression& other) const { return node::isEqual(this, other); }

    /** Implements `Node` interface. */
    auto properties() const { return node::Properties{}; }
};

} // namespace hilti::expression
