// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/type.h>
#include <hilti/ast/types/unknown.h>

namespace hilti {
namespace type {

namespace vector {

/** AST node for a vector iterator type. */
class Iterator : public TypeBase,
                 trait::isIterator,
                 trait::isDereferencable,
                 trait::isAllocable,
                 trait::isMutable,
                 trait::isRuntimeNonTrivial,
                 trait::isParameterized {
public:
    Iterator(Type ctype, bool const_, Meta m = Meta()) : TypeBase({std::move(ctype)}, std::move(m)), _const(const_) {}
    Iterator(Wildcard /*unused*/, Meta m = Meta()) : TypeBase({node::none}, std::move(m)), _wildcard(true) {}

    /** Returns the type of the container the iterator is working on. */
    Type containerType() const { return _wildcard ? type::unknown : type::effectiveType(child<Type>(0)); }

    /** Returns true if the container elements aren't modifiable. */
    bool isConstant() const { return _const; }

    /** Implements the `Type` interface. */
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }
    /** Implements the `Type` interface. */
    Type dereferencedType() const {
        return (_wildcard || containerType().isWildcard()) ? type::unknown : containerType().elementType();
    }
    /** Implements the `Type` interface. */
    auto isWildcard() const { return _wildcard; }
    /** Implements the `Type` interface. */
    auto typeParameters() const { return childs(); }
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
    Vector(Type t, Meta m = Meta()) : TypeBase({std::move(t)}, std::move(m)) {}
    Vector(Wildcard /*unused*/, Meta m = Meta()) : TypeBase({node::none}, std::move(m)), _wildcard(true) {}

    /** Implements the `Type` interface. */
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }
    /** Implements the `Type` interface. */
    Type elementType() const { return _wildcard ? type::unknown : type::effectiveType(child<Type>(0)); }
    /** Implements the `Type` interface. */
    Type iteratorType(bool const_) const { return vector::Iterator(*this, const_, meta()); }
    /** Implements the `Type` interface. */
    auto isWildcard() const { return _wildcard; }
    /** Implements the `Type` interface. */
    auto typeParameters() const { return childs(); }
    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }

    bool operator==(const Vector& other) const { return elementType() == other.elementType(); }

private:
    bool _wildcard = false;
};

} // namespace type
} // namespace hilti
