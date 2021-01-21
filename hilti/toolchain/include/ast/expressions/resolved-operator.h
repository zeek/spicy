// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>
#include <vector>

#include <hilti/ast/expression.h>
#include <hilti/ast/expressions/unresolved-operator.h>
#include <hilti/ast/node.h>
#include <hilti/ast/operator.h>
#include <hilti/ast/types/id.h>

namespace hilti {

namespace trait {
class isResolvedOperator {};
} // namespace trait

namespace expression {
namespace resolved_operator {
namespace detail {
#include <hilti/autogen/__resolved-operator.h>

inline Node to_node(ResolvedOperator t) { return Node(std::move(t)); }

inline std::ostream& operator<<(std::ostream& out, ResolvedOperator i) { return out << to_node(std::move(i)); }

} // namespace detail
} // namespace resolved_operator

using ResolvedOperator = resolved_operator::detail::ResolvedOperator;
using resolved_operator::detail::to_node;

namespace detail {

// Generally we want to compute the result type of operators dynamically
// because updates to their child nodes may lead to changes. For unresolved
// IDs, however, we need to store the type in the AST for it get to resolved.
// This function implements that distinction.
inline Type type_to_store(Type t) {
    if ( t.isA<type::UnresolvedID>() )
        return t;
    else
        return type::unknown;
}

} // namespace detail

/**
 * Base class for an AST node for an expression representing a resolved operator usage.
 *
 * @note Typically, one derives from this only by using the `__BEGIN_OPERATOR` macro.
 */
class ResolvedOperatorBase : public NodeBase, public trait::isExpression, public trait::isResolvedOperator {
public:
    ResolvedOperatorBase(const Operator& op, const std::vector<Expression>& operands, Meta meta = Meta())
        : NodeBase(nodes(detail::type_to_store(op.result(operands)), operands), std::move(meta)), _operator(op) {}

    const auto& operator_() const { return _operator; }
    auto kind() const { return _operator.kind(); }

    // ResolvedOperator interface with common implementation.
    const auto& operands() const {
        if ( _cache.operands.empty() )
            _cache.operands = childs<Expression>(1, -1);

        return _cache.operands;
    }

    const auto& result() const {
        if ( _cache.result )
            return *_cache.result;

        if ( ! childs()[0].isA<type::Unknown>() )
            _cache.result = child<Type>(0);
        else
            // If the result wasn't stored at instantiation time, try again.
            _cache.result = _operator.result(operands());

        return *_cache.result;
    }

    const auto& op0() const { return child<Expression>(1); }
    const auto& op1() const { return child<Expression>(2); }
    const auto& op2() const { return child<Expression>(3); }
    auto hasOp0() const { return ! childs().empty(); }
    auto hasOp1() const { return childs().size() >= 3; }
    auto hasOp2() const { return childs().size() >= 4; }
    void setOp0(const Expression& e) { childs()[1] = e; }
    void setOp1(const Expression& e) { childs()[2] = e; }
    void setOp2(const Expression& e) { childs()[3] = e; }

    bool operator==(const ResolvedOperator& other) const {
        return operator_() == other.operator_() && operands() == other.operands();
    }

    /** Implements `Expression` interface. */
    bool isLhs() const { return operator_().isLhs(); }
    /** Implements `Expression` interface. */
    bool isTemporary() const { return isLhs(); }
    /** Implements `Expression` interface. */
    auto type() const { return type::effectiveType(result()); }
    /** Implements `Expression` interface. */
    auto isEqual(const Expression& other) const { return node::isEqual(this, other); }

    /** Implements `Expression` interface. */
    bool isConstant() const { return type::isConstant(type()); }

    /** Implements `Node` interface. */
    auto properties() const { return node::Properties{{"kind", to_string(_operator.kind())}}; }
    /** Implements `Node` interface. */
    void clearCache() {
        _cache.result.reset();
        _cache.operands.clear();
    }

private:
    ::hilti::operator_::detail::Operator _operator;

    mutable struct {
        std::optional<Type> result;
        std::vector<Expression> operands;
    } _cache;
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
