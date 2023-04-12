// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/expression.h>

namespace hilti::expression {

/** AST node for a ternary expression. */
class Ternary : public NodeBase, public trait::isExpression {
public:
    Ternary(Expression cond, Expression true_, Expression false_, Meta m = Meta())
        : NodeBase({std::move(cond), std::move(true_), std::move(false_)}, std::move(m)) {}

    const auto& condition() const { return child<Expression>(0); }
    const auto& true_() const { return child<Expression>(1); }
    const auto& false_() const { return child<Expression>(2); }

    bool operator==(const Ternary& other) const {
        return condition() == other.condition() && true_() == other.true_() && false_() == other.false_();
    }

    void setFalse(const Expression& expr) { children()[2] = expr; }

    /** Implements `Expression` interface. */
    bool isLhs() const { return false; }
    /** Implements `Expression` interface. */
    bool isTemporary() const { return true_().isTemporary() || false_().isTemporary(); }
    /** Implements `Expression` interface. */
    const Type& type() const {
        return true_().type();
    } // TODO(robin): Currentluy we enforce both having the same type; we might need to coerce to target type though
    /** Implements `Expression` interface. */
    auto isConstant() const { return false; }
    /** Implements `Expression` interface. */
    auto isEqual(const Expression& other) const { return node::isEqual(this, other); }

    /** Implements `Node` interface. */
    auto properties() const { return node::Properties{}; }
};

} // namespace hilti::expression
