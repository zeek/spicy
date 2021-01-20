// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/expression.h>
#include <hilti/ast/types/bool.h>

namespace hilti {
namespace expression {

/** AST node for a logical "and" expression. */
class LogicalAnd : public NodeBase, public trait::isExpression {
public:
    LogicalAnd(Expression op0, Expression op1, Meta m = Meta())
        : NodeBase({std::move(op0), std::move(op1)}, std::move(m)) {}

    const auto& op0() const { return child<Expression>(0); }
    const auto& op1() const { return child<Expression>(1); }

    bool operator==(const LogicalAnd& other) const { return op0() == other.op0() && op1() == other.op1(); }

    /** Implements `Expression` interface. */
    bool isLhs() const { return false; }
    /** Implements `Expression` interface. */
    bool isTemporary() const { return true; }
    /** Implements `Expression` interface. */
    auto type() const { return type::Bool(); }
    /** Implements `Expression` interface. */
    auto isConstant() const { return op0().isConstant() && op1().isConstant(); }
    /** Implements `Expression` interface. */
    auto isEqual(const Expression& other) const { return node::isEqual(this, other); }

    /** Implements `Node` interface. */
    auto properties() const { return node::Properties{}; }

    /**
     * Returns a new "and" expression with the first operand expression replaced.
     *
     * @param e original expression
     * @param op new operand expresssion
     * @return new expression that's equal to original one but with the operand replaced
     */
    static Expression setOp0(const LogicalAnd& e, const Expression& op) {
        auto x = Expression(e)._clone().as<LogicalAnd>();
        x.childs()[0] = op;
        return x;
    }

    /**
     * Returns a new "and" expression with the second operand expression replaced.
     *
     * @param e original expression
     * @param op new operand expresssion
     * @return new expression that's equal to original one but with the operand replaced
     */
    static Expression setOp1(const LogicalAnd& e, const Expression& op) {
        auto x = Expression(e)._clone().as<LogicalAnd>();
        x.childs()[1] = op;
        return x;
    }
};

} // namespace expression
} // namespace hilti
