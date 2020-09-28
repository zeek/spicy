// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/expression.h>

namespace hilti {
namespace expression {

/** AST node for an expression that's being coerced from one type to another. */
class Coerced : public NodeBase, public trait::isExpression {
public:
    Coerced(Expression e, Type t, Meta m = Meta()) : NodeBase({std::move(e), std::move(t)}, std::move(m)) {}

    auto expression() const { return child<Expression>(0); }

    bool operator==(const Coerced& other) const { return expression() == other.expression() && type() == other.type(); }

    /** Implements `Expression` interface. */
    bool isLhs() const { return expression().isLhs(); }
    /** Implements `Expression` interface. */
    bool isTemporary() const { return true; }
    /** Implements `Expression` interface. */
    Type type() const { return type::nonConstant(type::effectiveType(child<Type>(1))); }
    /** Implements `Expression` interface. */
    auto isConstant() const { return expression().isConstant(); }
    /** Implements `Expression` interface. */
    auto isEqual(const Expression& other) const { return node::isEqual(this, other); }

    /** Implements `Node` interface. */
    auto properties() const { return node::Properties{}; }
};

} // namespace expression
} // namespace hilti
