// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/declarations/local-variable.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/statement.h>

namespace hilti {
namespace statement {

/** AST node for a "while" statement. */
class For : public NodeBase, public hilti::trait::isStatement {
public:
    For(hilti::ID id, hilti::Expression seq, Statement body, Meta m = Meta())
        : NodeBase(nodes(std::move(id), std::move(seq), std::move(body)), std::move(m)) {}

    auto id() const { return child<ID>(0); }
    auto sequence() const { return child<hilti::Expression>(1); }
    auto body() const { return child<hilti::Statement>(2); }

    /**
     * Returns the body's scope. Note that the scope is shared among any
     * copies of an instance.
     */
    std::shared_ptr<Scope> scope() const { return childs()[2].scope(); }

    bool operator==(const For& other) const {
        return id() == other.id() && sequence() == other.sequence() && body() == other.body();
    }

    /** Internal method for use by builder API only. */
    auto& _sequenceNode() { return childs()[1]; }

    /** Internal method for use by builder API only. */
    auto& _bodyNode() { return childs()[2]; }

    /** Implements the `Statement` interface. */
    auto isEqual(const Statement& other) const { return node::isEqual(this, other); }

    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }
};

} // namespace statement
} // namespace hilti
