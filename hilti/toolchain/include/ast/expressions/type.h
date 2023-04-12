// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/expression.h>
#include <hilti/ast/types/type.h>

namespace hilti::expression {

/** AST node for a type expression. */
class Type_ : public NodeBase, public trait::isExpression {
public:
    Type_(Type t, const Meta& m = Meta()) : NodeBase(nodes(type::Type_(std::move(t), m)), m) {}

    const auto& typeValue() const { return child<type::Type_>(0).typeValue(); }

    bool operator==(const Type_& other) const { return typeValue() == other.typeValue(); }

    /** Implements `Expression` interface. */
    bool isLhs() const { return false; }
    /** Implements `Expression` interface. */
    bool isTemporary() const { return true; }
    /** Implements `Expression` interface. */
    const auto& type() const { return child<Type>(0); }
    /** Implements `Expression` interface. */
    auto isConstant() const { return true; }
    /** Implements `Expression` interface. */
    auto isEqual(const Expression& other) const { return node::isEqual(this, other); }

    /** Implements `Node` interface. */
    auto properties() const { return node::Properties{}; }
};

} // namespace hilti::expression
