// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/expression.h>
#include <hilti/ast/statement.h>

namespace hilti::statement {

/** AST node for a ``continue`` statement. */
class Continue : public NodeBase, public hilti::trait::isStatement {
public:
    Continue(Meta m = Meta()) : NodeBase({}, std::move(m)) {}

    bool operator==(const Continue& /* other */) const { return true; }

    /** Implements the `Statement` interface. */
    auto isEqual(const Statement& other) const { return node::isEqual(this, other); }

    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }
};

} // namespace hilti::statement
