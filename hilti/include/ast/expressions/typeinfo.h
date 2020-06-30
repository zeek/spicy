// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/expression.h>
#include <hilti/ast/types/library.h>

namespace hilti {
namespace expression {

/** AST node for a "move" expression. */
class TypeInfo : public NodeBase, public trait::isExpression {
public:
    TypeInfo(Type t, Meta m = Meta()) : NodeBase({std::move(t)}, std::move(m)) {}

    auto infoType() const { return type::effectiveType(child<Type>(0)); }

    bool operator==(const TypeInfo& other) const { return infoType() == other.infoType(); }

    /** Implements `Expression` interface. */
    bool isLhs() const { return false; }
    /** Implements `Expression` interface. */
    bool isTemporary() const { return true; }
    /** Implements `Expression` interface. */
    auto type() const { return type::Library("const ::hilti::rt::TypeInfo*"); }
    /** Implements `Expression` interface. */
    auto isConstant() const { return true; }
    /** Implements `Expression` interface. */
    auto isEqual(const Expression& other) const { return node::isEqual(this, other); }

    /** Implements `Node` interface. */
    auto properties() const { return node::Properties{}; }
};

} // namespace expression
} // namespace hilti
