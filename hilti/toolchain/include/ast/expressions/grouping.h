// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/expression.h>
#include <hilti/ast/types/auto.h>

namespace hilti::expression {

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
    const auto& type() const { return expression().type(); }
    /** Implements `Expression` interface. */
    auto isConstant() const { return expression().isConstant(); }
    /** Implements `Expression` interface. */
    auto isEqual(const Expression& other) const { return node::isEqual(this, other); }

    /** Implements `Node` interface. */
    auto properties() const { return node::Properties{}; }
};

} // namespace hilti::expression
