// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/declarations/local-variable.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/statement.h>

namespace hilti::statement {

/** AST node for a "while" statement. */
class For : public NodeBase, public hilti::trait::isStatement {
public:
    For(hilti::ID id, hilti::Expression seq, Statement body, Meta m = Meta())
        : NodeBase(nodes(declaration::LocalVariable(std::move(id), true, id.meta()), std::move(seq), std::move(body)),
                   std::move(m)) {}

    const auto& local() const { return child<hilti::declaration::LocalVariable>(0); }
    auto localRef() const { return NodeRef(children()[0]); }
    const auto& sequence() const { return child<hilti::Expression>(1); }
    const auto& body() const { return child<hilti::Statement>(2); }

    void setLocalType(const Type& t) { children()[0].as<declaration::LocalVariable>().setType(t); }

    bool operator==(const For& other) const {
        return local() == other.local() && sequence() == other.sequence() && body() == other.body();
    }

    /** Internal method for use by builder API only. */
    auto& _sequenceNode() { return children()[1]; }

    /** Internal method for use by builder API only. */
    auto& _bodyNode() { return children()[2]; }

    /** Implements the `Statement` interface. */
    auto isEqual(const Statement& other) const { return node::isEqual(this, other); }

    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }
};

} // namespace hilti::statement
