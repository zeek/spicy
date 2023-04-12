// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/expression.h>
#include <hilti/ast/statement.h>

namespace hilti::statement {

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
     * @param e expression to evaluate at runtime
     * @param msg message to report an runtime if assertions fails
     * @param m meta information for AST node
     */
    Assert(::hilti::Expression expr, std::optional<::hilti::Expression> msg, Meta m = Meta())
        : NodeBase(nodes(std::move(expr), node::none, std::move(msg)), std::move(m)) {}

    /**
     * Creates an assert statement that expects an exception to occur when
     * the expression is evaluated.
     *
     * @param assert::Exception tag to select this constructor
     * @param e expression to evaluate at runtime
     * @param type exception type that's expected to be thrown when *e* is evaluated; unset of any exception
     * @param msg message to report an runtime if assertions fails
     * @param m meta information for AST node
     */
    Assert(assert::Exception /*unused*/, ::hilti::Expression expr, std::optional<Type> excpt,
           std::optional<::hilti::Expression> msg, Meta m = Meta())
        : NodeBase(nodes(std::move(expr), std::move(excpt), std::move(msg)), std::move(m)), _expects_exception(true) {}

    bool expectsException() const { return _expects_exception; }
    const auto& expression() const { return child<::hilti::Expression>(0); }
    auto exception() const { return children()[1].tryAs<Type>(); }
    auto message() const { return children()[2].tryAs<::hilti::Expression>(); }

    void setCondition(const hilti::Expression& c) { children()[0] = c; }

    bool operator==(const Assert& other) const {
        return _expects_exception == other._expects_exception && expression() == other.expression() &&
               exception() == other.exception() && message() == other.message();
    }

    /** Implements the `Statement` interface. */
    auto isEqual(const Statement& other) const { return node::isEqual(this, other); }

    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{{"expects-exception", _expects_exception}}; }

private:
    bool _expects_exception = false;
};

} // namespace hilti::statement
