// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/expression.h>
#include <hilti/ast/types/bool.h>

namespace hilti::expression {

/** AST node for a logical "not" expression. */
class LogicalNot : public NodeBase, public trait::isExpression {
public:
    LogicalNot(Expression e, const Meta& m = Meta()) : NodeBase(nodes(std::move(e), type::Bool(m)), m) {}

    const auto& expression() const { return child<Expression>(0); }

    void setExpression(const Expression& op) { children()[0] = op; }

    bool operator==(const LogicalNot& other) const { return expression() == other.expression(); }

    /** Implements `Expression` interface. */
    bool isLhs() const { return false; }
    /** Implements `Expression` interface. */
    bool isTemporary() const { return true; }
    /** Implements `Expression` interface. */
    const auto& type() const { return child<Type>(1); }
    /** Implements `Expression` interface. */
    auto isConstant() const { return expression().isConstant(); }
    /** Implements `Expression` interface. */
    auto isEqual(const Expression& other) const { return node::isEqual(this, other); }

    /** Implements `Node` interface. */
    auto properties() const { return node::Properties{}; }
};

} // namespace hilti::expression
