// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>
#include <vector>

#include <hilti/ast/statement.h>
#include <hilti/ast/statements/expression.h>

namespace hilti {
namespace statement {

/** AST node for a statement block. */
class Block : public NodeBase, public hilti::trait::isStatement {
public:
    Block(std::vector<Statement> stmts = {}, Meta m = Meta()) : NodeBase(nodes(std::move(stmts)), std::move(m)) {}

    auto statements() const { return childs<Statement>(0, -1); }

    bool operator==(const Block& /* other */) const {
        // return statements() == other.statements();
        return true; // FIXME
    }

    /** Internal method for use by builder API only. */
    void _add(Statement s) { addChild(std::move(s)); }

    /** Internal method for use by builder API only. */
    auto& _lastStatementNode() { return childs().back(); }

    /** Implements the `Statement` interface. */
    auto isEqual(const Statement& other) const { return node::isEqual(this, other); }

    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }
};

} // namespace statement
} // namespace hilti
