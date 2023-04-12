// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/expression.h>
#include <hilti/ast/statement.h>

namespace hilti::statement {

/** AST node for a "yield" statement. */
class Yield : public NodeBase, public hilti::trait::isStatement {
public:
    Yield(Meta m = Meta()) : NodeBase({}, std::move(m)) {}

    bool operator==(const Yield& /* other */) const { return true; }

    /** Implements the `Statement` interface. */
    auto isEqual(const Statement& other) const { return node::isEqual(this, other); }

    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }
};

} // namespace hilti::statement
