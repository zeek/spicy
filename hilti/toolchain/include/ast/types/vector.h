// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/type.h>
#include <hilti/ast/types/unknown.h>

namespace hilti::type {

namespace vector {

/** AST node for a vector iterator type. */
class Iterator : public TypeBase,
                 trait::isIterator,
                 trait::isDereferenceable,
                 trait::isAllocable,
                 trait::isMutable,
                 trait::isRuntimeNonTrivial,
                 trait::isParameterized {
public:
    Iterator(Type etype, bool const_, Meta m = Meta())
        : TypeBase(nodes(std::move(etype)), std::move(m)), _const(const_) {}
    Iterator(Wildcard /*unused*/, bool const_ = true, Meta m = Meta())
        : TypeBase(nodes(type::unknown), std::move(m)), _wildcard(true), _const(const_) {}

    /** Returns true if the container elements aren't modifiable. */
    bool isConstant() const { return _const; }

    /** Implements the `Type` interface. */
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }
    /** Implements the `Type` interface. */
    auto _isResolved(ResolvedState* rstate) const { return type::detail::isResolved(dereferencedType(), rstate); }
    /** Implements the `Type` interface. */
    const Type& dereferencedType() const { return child<Type>(0); }
    /** Implements the `Type` interface. */
    auto isWildcard() const { return _wildcard; }
    /** Implements the `Type` interface. */
    auto typeParameters() const { return children(); }
    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{{"const", _const}}; }

    bool operator==(const Iterator& other) const { return dereferencedType() == other.dereferencedType(); }

private:
    bool _wildcard = false;
    bool _const = false;
};

} // namespace vector

/** AST node for a vector type. */
class Vector : public TypeBase,
               trait::isAllocable,
               trait::isMutable,
               trait::isIterable,
               trait::isRuntimeNonTrivial,
               trait::isParameterized {
public:
    Vector(const Type& t, const Meta& m = Meta())
        : TypeBase(nodes(vector::Iterator(t, true, m), vector::Iterator(t, false, m)), m) {}
    Vector(Wildcard /*unused*/, const Meta& m = Meta())
        : TypeBase(nodes(vector::Iterator(Wildcard{}, true, m), vector::Iterator(Wildcard{}, false, m)), m),
          _wildcard(true) {}

    /** Implements the `Type` interface. */
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }
    /** Implements the `Type` interface. */
    auto _isResolved(ResolvedState* rstate) const {
        return type::detail::isResolved(iteratorType(true), rstate) &&
               type::detail::isResolved(iteratorType(false), rstate);
    }
    /** Implements the `Type` interface. */
    const Type& elementType() const { return child<vector::Iterator>(0).dereferencedType(); }
    /** Implements the `Type` interface. */
    const Type& iteratorType(bool const_) const { return const_ ? child<Type>(0) : child<Type>(1); }
    /** Implements the `Type` interface. */
    auto isWildcard() const { return _wildcard; }
    /** Implements the `Type` interface. */
    auto typeParameters() const { return children(); }
    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }

    bool operator==(const Vector& other) const { return elementType() == other.elementType(); }

private:
    bool _wildcard = false;
};

} // namespace hilti::type
