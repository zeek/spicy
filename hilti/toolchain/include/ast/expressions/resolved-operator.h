// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>
#include <vector>

#include <hilti/ast/expression.h>
#include <hilti/ast/expressions/unresolved-operator.h>
#include <hilti/ast/node.h>
#include <hilti/ast/operator.h>
#include <hilti/ast/types/unresolved-id.h>

namespace hilti {

namespace trait {
class isResolvedOperator {};
} // namespace trait

namespace expression {
namespace resolved_operator::detail {
#include <hilti/autogen/__resolved-operator.h>

inline Node to_node(ResolvedOperator t) { return Node(std::move(t)); }

inline std::ostream& operator<<(std::ostream& out, ResolvedOperator i) { return out << to_node(std::move(i)); }

} // namespace resolved_operator::detail

using ResolvedOperator = resolved_operator::detail::ResolvedOperator;

/**
 * Base class for an AST node for an expression representing a resolved operator usage.
 *
 * @note Typically, one derives from this only by using the `__BEGIN_OPERATOR` macro.
 */
class ResolvedOperatorBase : public NodeBase, public trait::isExpression, public trait::isResolvedOperator {
public:
    ResolvedOperatorBase(const Operator& op, const std::vector<Expression>& operands, Meta meta = Meta())
        : NodeBase(nodes(node::none, operands), std::move(meta)), _operator(op) {
        // Must not have instantiated this before we know the result type.
        children()[0] = type::pruneWalk(op.result(children<Expression>(1, -1)));
    }

    const auto& operator_() const { return _operator; }
    auto kind() const { return _operator.kind(); }

    // ResolvedOperator interface with common implementation.
    auto operands() const { return children<Expression>(1, -1); }
    const auto& result() const { return child<Type>(0); }
    const auto& op0() const { return child<Expression>(1); }
    const auto& op1() const { return child<Expression>(2); }
    const auto& op2() const { return child<Expression>(3); }
    auto hasOp0() const { return ! children().empty(); }
    auto hasOp1() const { return children().size() >= 3; }
    auto hasOp2() const { return children().size() >= 4; }
    void setOp0(const Expression& e) { children()[1] = e; }
    void setOp1(const Expression& e) { children()[2] = e; }
    void setOp2(const Expression& e) { children()[3] = e; }

    bool operator==(const ResolvedOperator& other) const {
        return operator_() == other.operator_() && operands() == other.operands();
    }

    /** Implements `Expression` interface. */
    bool isLhs() const { return operator_().isLhs(); }
    /** Implements `Expression` interface. */
    bool isTemporary() const { return isLhs(); }
    /** Implements `Expression` interface. */
    const Type& type() const { return result(); }
    /** Implements `Expression` interface. */
    auto isEqual(const Expression& other) const { return node::isEqual(this, other); }

    /** Implements `Expression` interface. */
    bool isConstant() const { return type::isConstant(type()); }

    /** Implements `Node` interface. */
    auto properties() const { return node::Properties{{"kind", to_string(_operator.kind())}}; }

private:
    ::hilti::operator_::detail::Operator _operator;
};

namespace resolved_operator {

/**
 * Copies an existing resolved operator, replacing its 1st operand with a different expression.
 *
 * @param r original operator
 * @param e new operand
 * @return new resolved operator with the 1st operand replaced
 */
inline hilti::Expression setOp0(const expression::ResolvedOperator& r, Expression e) {
    auto x = r._clone().as<expression::ResolvedOperator>();
    x.setOp0(std::move(e));
    return x;
}

/**
 * Copies an existing resolved operator, replacing its 2nd operand with a different expression.
 *
 * @param r original operator
 * @param e new operand
 * @return new resolved operator with the 2nd operand replaced
 */
inline hilti::Expression setOp1(const expression::ResolvedOperator& r, Expression e) {
    auto x = r._clone().as<expression::ResolvedOperator>();
    x.setOp1(std::move(e));
    return x;
}

/**
 * Copies an existing resolved operator, replacing its 3rd operand with a different expression.
 *
 * @param r original operator
 * @param e new operand
 * @return new resolved operator with the 3rd operand replaced
 */
inline hilti::Expression setOp2(const expression::ResolvedOperator& r, Expression e) {
    auto x = r._clone().as<expression::ResolvedOperator>();
    x.setOp2(std::move(e));
    return x;
}

} // namespace resolved_operator
} // namespace expression
} // namespace hilti
