// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/declarations/local-variable.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/statement.h>
#include <hilti/base/logger.h>

namespace hilti {
namespace statement {

/** AST node for a "if" statement. */
class If : public NodeBase, public hilti::trait::isStatement {
public:
    If(const hilti::Declaration& init, std::optional<hilti::Expression> cond, Statement true_,
       std::optional<Statement> false_, Meta m = Meta())
        : NodeBase(nodes(init, std::move(cond), std::move(true_), std::move(false_)), std::move(m)) {
        if ( ! init.isA<declaration::LocalVariable>() )
            logger().internalError("initialization for 'if' must be a local declaration");
    }

    If(hilti::Expression cond, Statement true_, std::optional<Statement> false_, Meta m = Meta())
        : NodeBase(nodes(node::none, std::move(cond), std::move(true_), std::move(false_)), std::move(m)) {}

    auto init() const { return childs()[0].tryAs<hilti::Declaration>(); }
    auto condition() const { return childs()[1].tryAs<hilti::Expression>(); }
    auto true_() const { return child<hilti::Statement>(2); }
    auto false_() const { return childs()[3].tryAs<Statement>(); }

    bool operator==(const If& other) const {
        return init() == other.init() && condition() == other.condition() && true_() == other.true_() &&
               false_() == other.false_();
    }

    /** Internal method for use by builder API only. */
    auto& _trueNode() { return childs()[2]; }

    /** Internal method for use by builder API only. */
    auto& _falseNode() { return childs()[3]; }

    /** Implements the `Statement` interface. */
    auto isEqual(const Statement& other) const { return node::isEqual(this, other); }

    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }

    /**
     * Returns a new "if" statement with the init expression replaced.
     *
     * @param e original statement
     * @param d new init expresssion
     * @return new statement that's equal to original one but with the init expression replaced
     */
    static Statement setInit(const If& e, const hilti::Declaration& d) {
        auto x = Statement(e)._clone().as<If>();
        x.childs()[0] = d;
        return x;
    }

    /**
     * Returns a new "if" statement with the condition expression replaced.
     *
     * @param e original statement
     * @param c new condition expresssion
     * @return new statement that's equal to original one but with the condition replaced
     */
    static Statement setCondition(const If& e, const hilti::Expression& c) {
        auto x = Statement(e)._clone().as<If>();
        x.childs()[1] = c;
        return x;
    }
};

} // namespace statement
} // namespace hilti
