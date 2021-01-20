// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/expression.h>

namespace hilti {
namespace expression {

/** AST node for grouping another expression inside parentheses. */
class Grouping : public NodeBase, public trait::isExpression {
public:
    Grouping(Expression e, Meta m = Meta()) : NodeBase({std::move(e)}, std::move(m)) {}

    const auto& expression() const { return child<Expression>(0); }

    bool operator==(const Grouping& other) const { return expression() == other.expression(); }

    /** Implements `Expression` interface. */
    bool isLhs() const { return expression().isLhs(); }
    /** Implements `Expression` interface. */
    bool isTemporary() const { return expression().isTemporary(); }
    /** Implements `Expression` interface. */
    auto type() const { return type::effectiveType(expression().type()); }
    /** Implements `Expression` interface. */
    auto isConstant() const { return expression().isConstant(); }
    /** Implements `Expression` interface. */
    auto isEqual(const Expression& other) const { return node::isEqual(this, other); }

    /** Implements `Node` interface. */
    auto properties() const { return node::Properties{}; }
};

} // namespace expression
} // namespace hilti
