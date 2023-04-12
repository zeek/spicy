// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/expression.h>
#include <hilti/ast/statement.h>

namespace hilti::statement {

/** AST node for an expression statement. */
class Expression : public NodeBase, public hilti::trait::isStatement {
public:
    Expression(hilti::Expression e, Meta m = Meta()) : NodeBase({std::move(e)}, std::move(m)) {}

    const auto& expression() const { return child<::hilti::Expression>(0); }

    bool operator==(const Expression& other) const { return expression() == other.expression(); }

    /** Implements the `Statement` interface. */
    auto isEqual(const Statement& other) const { return node::isEqual(this, other); }

    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }
};

} // namespace hilti::statement
