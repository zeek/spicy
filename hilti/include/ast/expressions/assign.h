// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/expression.h>

namespace hilti {
namespace expression {

/** AST node for an assign expression. */
class Assign : public NodeBase, public trait::isExpression {
public:
    Assign(Expression target, Expression src, Meta m = Meta())
        : NodeBase({std::move(target), std::move(src)}, std::move(m)) {}

    auto target() const { return child<Expression>(0); }
    auto source() const { return child<Expression>(1); }

    bool operator==(const Assign& other) const { return target() == other.target() && source() == other.source(); }

    /** Implements `Expression` interface. */
    bool isLhs() const { return target().isLhs(); }
    /** Implements `Expression` interface. */
    bool isTemporary() const { return isLhs(); }
    /** Implements `Expression` interface. */
    auto type() const { return type::effectiveType(target().type()); }
    /** Implements `Expression` interface. */
    auto isConstant() const { return false; }
    /** Implements `Expression` interface. */
    auto isEqual(const Expression& other) const { return node::isEqual(this, other); }

    /** Implements `Node` interface. */
    auto properties() const { return node::Properties{}; }

    /**
     * Returns a new assign expression with the target expression replaced.
     *
     * @param e original expression
     * @param t new target expresssion
     * @return new expression that's equal to original one but with the target expression replaced
     */
    static Expression setTarget(const Assign& e, const Expression& t) {
        auto x = Expression(e)._clone().as<Assign>();
        x.childs()[0] = t;
        return x;
    }

    /**
     * Returns a new assign expression with the source expression replaced.
     *
     * @param e original expression
     * @param s new source expresssion
     * @return new expression that's equal to original one but with the source expression replaced
     */
    static Expression setSource(const Assign& e, const Expression& s) {
        auto x = Expression(e)._clone().as<Assign>();
        x.childs()[1] = s;
        return x;
    }
};

} // namespace expression
} // namespace hilti
