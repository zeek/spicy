// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/declarations/local-variable.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/statement.h>
#include <hilti/base/logger.h>

namespace hilti::statement {

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

    auto init() const { return children()[0].tryAs<hilti::declaration::LocalVariable>(); }
    auto initRef() const {
        return children()[0].isA<hilti::declaration::LocalVariable>() ? NodeRef(children()[0]) : NodeRef();
    }
    auto condition() const { return children()[1].tryAs<hilti::Expression>(); }
    const auto& true_() const { return child<hilti::Statement>(2); }
    auto false_() const { return children()[3].tryAs<Statement>(); }

    void setCondition(const hilti::Expression& e) { children()[1] = e; }
    void removeFalse() { children()[3] = node::none; }

    bool operator==(const If& other) const {
        return init() == other.init() && condition() == other.condition() && true_() == other.true_() &&
               false_() == other.false_();
    }

    /** Internal method for use by builder API only. */
    auto& _trueNode() { return children()[2]; }

    /** Internal method for use by builder API only. */
    auto& _falseNode() { return children()[3]; }

    /** Implements the `Statement` interface. */
    auto isEqual(const Statement& other) const { return node::isEqual(this, other); }

    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }
};

} // namespace hilti::statement
