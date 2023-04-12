// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/expression.h>

namespace hilti::expression {

/** AST node for an expression wrapped to have a specific type. */
class TypeWrapped : public NodeBase, public trait::isExpression {
public:
    TypeWrapped(Expression e, Type t, Meta m = Meta()) : NodeBase(nodes(std::move(e), std::move(t)), std::move(m)) {}

    const auto& expression() const { return child<Expression>(0); }

    bool operator==(const TypeWrapped& other) const {
        return expression() == other.expression() && type() == other.type();
    }

    /** Implements `Expression` interface. */
    bool isLhs() const { return expression().isLhs(); }
    /** Implements `Expression` interface. */
    bool isTemporary() const { return expression().isTemporary(); }
    /** Implements `Expression` interface. */
    const Type& type() const { return children()[1].as<Type>(); }

    /** Implements `Expression` interface. */
    auto isConstant() const { return expression().isConstant(); }
    /** Implements `Expression` interface. */
    auto isEqual(const Expression& other) const { return node::isEqual(this, other); }

    /** Implements `Node` interface. */
    auto properties() const { return node::Properties{}; }
};

} // namespace hilti::expression
