// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/declarations/local-variable.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/statement.h>

namespace hilti {
namespace statement {

/** AST node for a "while" statement. */
class While : public NodeBase, public hilti::trait::isStatement {
public:
    While(const hilti::Declaration& init, std::optional<hilti::Expression> cond, Statement body,
          std::optional<Statement> else_ = {}, Meta m = Meta())
        : NodeBase(nodes(init, std::move(cond), std::move(body), std::move(else_)), std::move(m)) {
        if ( ! init.isA<declaration::LocalVariable>() )
            logger().internalError("initialization for 'while' must be a local declaration");
    }

    While(hilti::Expression cond, Statement body, Meta m = Meta())
        : NodeBase(nodes(node::none, std::move(cond), std::move(body), node::none), std::move(m)) {}

    While(hilti::Expression cond, Statement body, std::optional<Statement> else_, Meta m = Meta())
        : NodeBase(nodes(node::none, std::move(cond), std::move(body), std::move(else_)), std::move(m)) {}

    auto init() const { return childs()[0].tryReferenceAs<hilti::Declaration>(); }
    auto condition() const { return childs()[1].tryReferenceAs<hilti::Expression>(); }
    const auto& body() const { return child<hilti::Statement>(2); }
    auto else_() const { return childs()[3].tryReferenceAs<Statement>(); }

    bool operator==(const While& other) const {
        return init() == other.init() && condition() == other.condition() && body() == other.body() &&
               else_() == other.else_();
    }

    /** Internal method for use by builder API only. */
    auto& _bodyNode() { return childs()[2]; }

    /** Internal method for use by builder API only. */
    auto& _elseNode() { return childs()[3]; }

    /** Implements the `Statement` interface. */
    auto isEqual(const Statement& other) const { return node::isEqual(this, other); }

    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }

    /**
     * Returns a new "while" statement with the init expression replaced.
     *
     * @param e original statement
     * @param d new init expresssion
     * @return new statement that's equal to original one but with the init expression replaced
     */
    static Statement setInit(const While& e, const hilti::Declaration& d) {
        auto x = Statement(e)._clone().as<While>();
        x.childs()[0] = d;
        return x;
    }

    /**
     * Returns a new "while" statement with the condition expression replaced.
     *
     * @param d original statement
     * @param c new condition expresssion
     * @return new statement that's equal to original one but with the condition replaced
     */
    static Statement setCondition(const While& e, const hilti::Expression& c) {
        auto x = Statement(e)._clone().as<While>();
        x.childs()[1] = c;
        return x;
    }
};

} // namespace statement
} // namespace hilti
