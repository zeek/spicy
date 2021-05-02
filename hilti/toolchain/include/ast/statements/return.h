// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/expression.h>
#include <hilti/ast/statement.h>

namespace hilti {
namespace statement {

/** AST node for a "return" statement. */
class Return : public NodeBase, public hilti::trait::isStatement {
public:
    Return(Meta m = Meta()) : NodeBase({node::none}, std::move(m)) {}
    Return(hilti::Expression e, Meta m = Meta()) : NodeBase({std::move(e)}, std::move(m)) {}

    auto expression() const { return childs()[0].tryAs<hilti::Expression>(); }

    void setExpression(hilti::Expression c) { childs()[0] = std::move(c); }

    bool operator==(const Return& other) const { return expression() == other.expression(); }

    /** Implements the `Statement` interface. */
    auto isEqual(const Statement& other) const { return node::isEqual(this, other); }

    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }
};

} // namespace statement
} // namespace hilti
