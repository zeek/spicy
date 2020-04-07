// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/expression.h>
#include <hilti/ast/types/bool.h>

namespace hilti {
namespace expression {

/** AST node for a logical "or" expression. */
class LogicalOr : public NodeBase, public trait::isExpression {
public:
    LogicalOr(Expression op0, Expression op1, Meta m = Meta())
        : NodeBase({std::move(op0), std::move(op1)}, std::move(m)) {}

    auto op0() const { return child<Expression>(0); }
    auto op1() const { return child<Expression>(1); }

    bool operator==(const LogicalOr& other) const { return op0() == other.op0() && op1() == other.op1(); }

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
     * Returns a new "or" expression with the first operand expression replaced.
     *
     * @param e original expression
     * @param op new operand expresssion
     * @return new expression that's equal to original one but with the operand replaced
     */
    static Expression setOp0(const LogicalOr& e, const Expression& op) {
        auto x = Expression(e)._clone().as<LogicalOr>();
        x.childs()[0] = op;
        return x;
    }

    /**
     * Returns a new "or" expression with the second operand expression replaced.
     *
     * @param e original expression
     * @param op new operand expresssion
     * @return new expression that's equal to original one but with the operand replaced
     */
    static Expression setOp1(const LogicalOr& e, const Expression& op) {
        auto x = Expression(e)._clone().as<LogicalOr>();
        x.childs()[1] = op;
        return x;
    }
};

} // namespace expression
} // namespace hilti
