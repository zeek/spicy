// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/expression.h>
#include <hilti/ast/types/bool.h>

namespace hilti {
namespace expression {

/** AST node for a logical "not" expression. */
class LogicalNot : public NodeBase, public trait::isExpression {
public:
    LogicalNot(Expression e, Meta m = Meta()) : NodeBase({std::move(e)}, std::move(m)) {}

    auto expression() const { return child<Expression>(0); }

    bool operator==(const LogicalNot& other) const { return expression() == other.expression(); }

    /** Implements `Expression` interface. */
    bool isLhs() const { return false; }
    /** Implements `Expression` interface. */
    bool isTemporary() const { return true; }
    /** Implements `Expression` interface. */
    auto type() const { return type::Bool(); }
    /** Implements `Expression` interface. */
    auto isConstant() const { return expression().isConstant(); }
    /** Implements `Expression` interface. */
    auto isEqual(const Expression& other) const { return node::isEqual(this, other); }

    /** Implements `Node` interface. */
    auto properties() const { return node::Properties{}; }

    /**
     * Returns a new "not" expression with the operand expression replaced.
     *
     * @param e original expression
     * @param op new operand expresssion
     * @return new expression that's equal to original one but with the operand replaced
     */
    static Expression setExpression(const LogicalNot& e, const Expression& op) {
        auto x = Expression(e)._clone().as<LogicalNot>();
        x.childs()[0] = op;
        return x;
    }
};

} // namespace expression
} // namespace hilti
