// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/expression.h>
#include <hilti/ast/statement.h>

namespace hilti {
namespace statement {

/** AST node for a "throw" statement. */
class Throw : public NodeBase, public hilti::trait::isStatement {
public:
    Throw(Meta m = Meta()) : NodeBase({node::none}, std::move(m)) {}
    Throw(hilti::Expression excpt, Meta m = Meta()) : NodeBase({std::move(excpt)}, std::move(m)) {}

    auto expression() const { return childs()[0].tryReferenceAs<hilti::Expression>(); }

    bool operator==(const Throw& other) const { return expression() == other.expression(); }

    /** Implements the `Statement` interface. */
    auto isEqual(const Statement& other) const { return node::isEqual(this, other); }

    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }
};

} // namespace statement
} // namespace hilti
