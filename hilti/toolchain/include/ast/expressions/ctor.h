// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/ctor.h>
#include <hilti/ast/expression.h>

namespace hilti::expression {

/** AST node for a constructor expression. */
class Ctor : public NodeBase, public trait::isExpression {
public:
    Ctor(hilti::Ctor c, Meta m = Meta()) : NodeBase({std::move(c)}, std::move(m)) {}

    const auto& ctor() const { return child<::hilti::Ctor>(0); }

    bool operator==(const Ctor& other) const { return ctor() == other.ctor(); }

    /** Implements `Expression` interface. */
    bool isLhs() const { return ctor().isLhs(); }
    /** Implements `Expression` interface. */
    bool isTemporary() const { return ctor().isTemporary(); }
    /** Implements `Expression` interface. */
    const auto& type() const { return ctor().type(); }
    /** Implements `Expression` interface. */
    auto isConstant() const { return ctor().isConstant(); }
    /** Implements `Expression` interface. */
    auto isEqual(const Expression& other) const { return node::isEqual(this, other); }

    /** Implements `Node` interface. */
    auto properties() const { return node::Properties{}; }
};

} // namespace hilti::expression
