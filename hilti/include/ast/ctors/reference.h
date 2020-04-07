// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/ctor.h>
#include <hilti/ast/ctors/null.h>
#include <hilti/ast/expressions/ctor.h>
#include <hilti/ast/types/reference.h>

namespace hilti {
namespace ctor {

/** AST node for a constructor for a `ref<T>` value (which can only be null). */
class StrongReference : public NodeBase, public hilti::trait::isCtor {
public:
    /** Constructs a null value of type `t`. */
    StrongReference(Type t, Meta m = Meta()) : NodeBase({std::move(t)}, std::move(m)) {}

    Type dereferencedType() const { return type::effectiveType(child<Type>(0)); }

    bool operator==(const StrongReference& other) const { return dereferencedType() == other.dereferencedType(); }

    /** Implements `Ctor` interface. */
    Type type() const { return type::StrongReference(dereferencedType(), meta()); }

    /** Implements `Ctor` interface. */
    bool isConstant() const { return true; }
    /** Implements `Ctor` interface. */
    bool isLhs() const { return false; }
    /** Implements `Ctor` interface. */
    auto isTemporary() const { return true; }

    /** Implements `Ctor` interface. */
    auto isEqual(const Ctor& other) const { return node::isEqual(this, other); }

    /** Implements `Node` interface. */
    auto properties() const { return node::Properties{}; }
};

/** AST node for a constructor for a `weak_ref<T>` value (which can only be null). */
class WeakReference : public NodeBase, public hilti::trait::isCtor {
public:
    /** Constructs a null value of type `t`. */
    WeakReference(Type t, Meta m = Meta()) : NodeBase({std::move(t)}, std::move(m)) {}

    Type dereferencedType() const { return type::effectiveType(child<Type>(0)); }

    bool operator==(const WeakReference& other) const { return dereferencedType() == other.dereferencedType(); }

    /** Implements `Ctor` interface. */
    Type type() const { return type::WeakReference(dereferencedType(), meta()); }

    /** Implements `Ctor` interface. */
    bool isConstant() const { return true; }
    /** Implements `Ctor` interface. */
    bool isLhs() const { return false; }
    /** Implements `Ctor` interface. */
    auto isTemporary() const { return true; }

    /** Implements `Ctor` interface. */
    auto isEqual(const Ctor& other) const { return node::isEqual(this, other); }

    /** Implements `Node` interface. */
    auto properties() const { return node::Properties{}; }
};

/** AST node for a constructor for a `value_ref<T>` instance. */
class ValueReference : public NodeBase, public hilti::trait::isCtor {
public:
    /** Constructs a reference value of type `t`. */
    ValueReference(Expression e, Meta m = Meta()) : NodeBase({std::move(e)}, std::move(m)) {}

    const Expression& expression() const { return child<Expression>(0); }
    Type dereferencedType() const { return child<Expression>(0).type(); }

    bool operator==(const ValueReference& other) const { return dereferencedType() == other.dereferencedType(); }

    /** Implements `Ctor` interface. */
    Type type() const { return type::ValueReference(dereferencedType(), meta()); }
    /** Implements `Ctor` interface. */
    bool isConstant() const { return true; }
    /** Implements `Ctor` interface. */
    bool isLhs() const { return false; }
    /** Implements `Ctor` interface. */
    auto isTemporary() const { return true; }

    /** Implements `Ctor` interface. */
    auto isEqual(const Ctor& other) const { return node::isEqual(this, other); }

    /** Implements `Node` interface. */
    auto properties() const { return node::Properties{}; }
};

} // namespace ctor
} // namespace hilti
