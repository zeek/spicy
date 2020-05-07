// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/expression.h>
#include <hilti/ast/statement.h>

namespace hilti {
namespace statement {

namespace assert {
/**
 * Tag for `Assert` to constructor to create an assertion expecting an
 * exception to occur.
 */
struct Exception {};
} // namespace assert

/** AST node for an assert statement. */
class Assert : public NodeBase, public hilti::trait::isStatement {
public:
    /**
     * Creates an assert statement that expects an exception to evaluate to true at runtime.
     *
     * @param expr expression to evaluate at runtime
     * @param msg message to report an runtime if assertions fails
     * @param m meta informatio for AST node
     */
    Assert(::hilti::Expression expr, std::optional<::hilti::Expression> msg, Meta m = Meta())
        : NodeBase(nodes(std::move(expr), node::none, std::move(msg)), std::move(m)) {}

    /**
     * Creates an assert statement that expects an exception to occur when
     * the expression is evaluated.
     *
     * @param expr expression to evaluate at runtime
     * @param excpt exception type that's expected to be thrown when *e* is evaluated; unset of any exception
     * @param msg message to report an runtime if assertions fails
     * @param m meta informatio for AST node
     */
    Assert(assert::Exception /*unused*/, ::hilti::Expression expr, std::optional<Type> excpt,
           std::optional<::hilti::Expression> msg, Meta m = Meta())
        : NodeBase(nodes(std::move(expr), std::move(excpt), std::move(msg)), std::move(m)), _expects_exception(true) {}

    bool expectsException() const { return _expects_exception; }
    auto expression() const { return child<::hilti::Expression>(0); }
    auto exception() const { return type::effectiveOptionalType(childs()[1].tryAs<Type>()); }
    auto message() const { return childs()[2].tryAs<::hilti::Expression>(); }

    bool operator==(const Assert& other) const {
        return _expects_exception == other._expects_exception && expression() == other.expression() &&
               exception() == other.exception() && message() == other.message();
    }

    /** Implements the `Statement` interface. */
    auto isEqual(const Statement& other) const { return node::isEqual(this, other); }

    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{{"expects-exception", _expects_exception}}; }

    /**
     * Returns a new `assert` statement with the expression replaced.
     *
     * @param e original statement
     * @param c new expresssion
     * @return new statement that's equal to original one but with the expression replaced
     */
    static Statement setCondition(const Assert& e, const hilti::Expression& c) {
        auto x = Statement(e)._clone().as<Assert>();
        x.childs()[0] = c;
        return x;
    }

private:
    bool _expects_exception = false;
};

} // namespace statement
} // namespace hilti
