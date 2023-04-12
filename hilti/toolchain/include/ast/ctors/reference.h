// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/ctor.h>
#include <hilti/ast/ctors/null.h>
#include <hilti/ast/expressions/ctor.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/auto.h>
#include <hilti/ast/types/reference.h>

namespace hilti::ctor {

/** AST node for a constructor for a `ref<T>` value (which can only be null). */
class StrongReference : public NodeBase, public hilti::trait::isCtor {
public:
    /** Constructs a null value of type `t`. */
    StrongReference(const Type& t, const Meta& m = Meta()) : NodeBase(nodes(t, type::StrongReference(t, m)), m) {}

    const Type& dereferencedType() const { return child<Type>(0); }

    bool operator==(const StrongReference& other) const { return dereferencedType() == other.dereferencedType(); }

    /** Implements `Ctor` interface. */
    const Type& type() const { return child<Type>(1); }

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
    WeakReference(const Type& t, const Meta& m = Meta()) : NodeBase(nodes(t, type::WeakReference(t, m)), m) {}

    const Type& dereferencedType() const { return child<Type>(0); }

    bool operator==(const WeakReference& other) const { return dereferencedType() == other.dereferencedType(); }

    /** Implements `Ctor` interface. */
    const Type& type() const { return child<Type>(1); }

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
    ValueReference(Expression e, Meta m = Meta())
        : NodeBase(nodes(type::ValueReference(type::auto_, m), std::move(e)), std::move(m)) {}

    const Type& dereferencedType() const { return child<type::ValueReference>(0).dereferencedType(); }
    const Expression& expression() const { return child<Expression>(1); }

    void setDereferencedType(Type x) { children()[0] = type::ValueReference(std::move(x)); }

    bool operator==(const ValueReference& other) const { return dereferencedType() == other.dereferencedType(); }

    /** Implements `Ctor` interface. */
    const Type& type() const { return child<Type>(0); }
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

} // namespace hilti::ctor
