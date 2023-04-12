// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/expression.h>
#include <hilti/ast/types/bool.h>

namespace hilti::expression {

/** AST node for a logical "and" expression. */
class LogicalAnd : public NodeBase, public trait::isExpression {
public:
    LogicalAnd(Expression op0, Expression op1, const Meta& m = Meta())
        : NodeBase(nodes(std::move(op0), std::move(op1), type::Bool(m)), m) {}

    const auto& op0() const { return child<Expression>(0); }
    const auto& op1() const { return child<Expression>(1); }

    void setOp0(const Expression& op) { children()[0] = op; }
    void setOp1(const Expression& op) { children()[1] = op; }

    bool operator==(const LogicalAnd& other) const { return op0() == other.op0() && op1() == other.op1(); }

    /** Implements `Expression` interface. */
    bool isLhs() const { return false; }
    /** Implements `Expression` interface. */
    bool isTemporary() const { return true; }
    /** Implements `Expression` interface. */
    const auto& type() const { return child<Type>(2); }
    /** Implements `Expression` interface. */
    auto isConstant() const { return op0().isConstant() && op1().isConstant(); }
    /** Implements `Expression` interface. */
    auto isEqual(const Expression& other) const { return node::isEqual(this, other); }

    /** Implements `Node` interface. */
    auto properties() const { return node::Properties{}; }
};

} // namespace hilti::expression
