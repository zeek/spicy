// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/declarations/local-variable.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/statement.h>
#include <hilti/base/logger.h>

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

    auto init() const { return childs()[0].tryAs<hilti::declaration::LocalVariable>(); }
    auto initRef() const {
        return childs()[0].isA<hilti::declaration::LocalVariable>() ? NodeRef(childs()[0]) : NodeRef();
    }
    auto condition() const { return childs()[1].tryAs<hilti::Expression>(); }
    const auto& body() const { return child<hilti::Statement>(2); }
    auto else_() const { return childs()[3].tryAs<Statement>(); }

    void setCondition(hilti::Expression c) { childs()[1] = std::move(c); }
    void setInit(hilti::Expression c) { childs()[0] = std::move(c); }

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
};

} // namespace statement
} // namespace hilti
