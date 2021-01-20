// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/expression.h>
#include <hilti/ast/types/type.h>

namespace hilti {
namespace expression {

/** AST node for a type expression. */
class Type_ : public NodeBase, public trait::isExpression {
public:
    Type_(Type t, Meta m = Meta()) : NodeBase({std::move(t)}, std::move(m)) {}

    auto typeValue() const { return type::effectiveType(child<Type>(0)); }

    bool operator==(const Type_& other) const { return typeValue() == other.typeValue(); }

    /** Implements `Expression` interface. */
    bool isLhs() const { return false; }
    /** Implements `Expression` interface. */
    bool isTemporary() const { return true; }
    /** Implements `Expression` interface. */
    auto type() const { return type::Type_(child<Type>(0)); }
    /** Implements `Expression` interface. */
    auto isConstant() const { return true; }
    /** Implements `Expression` interface. */
    auto isEqual(const Expression& other) const { return node::isEqual(this, other); }

    /** Implements `Node` interface. */
    auto properties() const { return node::Properties{}; }
};

} // namespace expression
} // namespace hilti
