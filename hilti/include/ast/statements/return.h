// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/expression.h>
#include <hilti/ast/statement.h>

namespace hilti {
namespace statement {

/** AST node for a "return" statement. */
class Return : public NodeBase, public hilti::trait::isStatement {
public:
    Return(Meta m = Meta()) : NodeBase({}, std::move(m)) {}
    Return(hilti::Expression e, Meta m = Meta()) : NodeBase({std::move(e)}, std::move(m)) {}

    std::optional<hilti::Expression> expression() const {
        if ( ! childs().empty() )
            return child<::hilti::Expression>(0);

        return {};
    }

    bool operator==(const Return& other) const { return expression() == other.expression(); }

    /** Implements the `Statement` interface. */
    auto isEqual(const Statement& other) const { return node::isEqual(this, other); }

    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }

    /**
     * Returns a new "return" statement with the expression replaced.
     *
     * @param e original statement
     * @param c new expresssion
     * @return new statement that's equal to original one but with the expression replaced
     */
    static Statement setExpression(const Return& e, const hilti::Expression& c) {
        auto x = Statement(e)._clone().as<Return>();
        x.childs()[0] = c;
        return x;
    }
};

} // namespace statement
} // namespace hilti
