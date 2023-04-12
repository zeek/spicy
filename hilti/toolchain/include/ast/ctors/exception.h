// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/ctor.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/types/exception.h>

namespace hilti::ctor {

/** AST node for a string constructor. */
class Exception : public NodeBase, public hilti::trait::isCtor {
public:
    Exception(Type t, Expression msg, Meta m = Meta()) : NodeBase({std::move(t), std::move(msg)}, std::move(m)) {}

    const auto& value() const { return child<Expression>(1); }

    bool operator==(const Exception& other) const { return type() == other.type() && value() == other.value(); }

    /** Implements `Ctor` interface. */
    const Type& type() const { return child<Type>(0); }
    /** Implements `Ctor` interface. */
    bool isConstant() const { return true; }
    /** Implements `Ctor` interface. */
    auto isLhs() const { return false; }
    /** Implements `Ctor` interface. */
    auto isTemporary() const { return true; }
    /** Implements `Ctor` interface. */
    auto isEqual(const Ctor& other) const { return node::isEqual(this, other); }

    /** Implements `Node` interface. */
    auto properties() const { return node::Properties{}; }
};

} // namespace hilti::ctor
