// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/type.h>
#include <hilti/ast/types/integer.h>

namespace hilti::type {

namespace bytes {

/** AST node for a list iterator type. */
class Iterator : public TypeBase,
                 trait::isIterator,
                 trait::isDereferenceable,
                 trait::isAllocable,
                 trait::isMutable,
                 trait::isRuntimeNonTrivial {
public:
    Iterator(Meta m = Meta()) : TypeBase(nodes(Type(type::UnsignedInteger(8))), std::move(m)) {}

    bool operator==(const Iterator& /* other */) const { return true; }

    /** Implements the `Type` interface. */
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }
    /** Implements the `Type` interface. */
    auto _isResolved(ResolvedState* rstate) const { return true; }
    /** Implements the `Type` interface. */
    const Type& dereferencedType() const { return child<Type>(0); }
    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }
};

} // namespace bytes

/** AST node for a bytes type. */
class Bytes : public TypeBase,
              trait::isAllocable,
              trait::isMutable,
              trait::isIterable,
              trait::isRuntimeNonTrivial,
              trait::isSortable {
public:
    Bytes(const Meta& m = Meta()) : TypeBase(nodes(Type(type::UnsignedInteger(8)), Type(bytes::Iterator(m))), m) {}

    bool operator==(const Bytes& /* other */) const { return true; }

    /** Implements the `Type` interface. */
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }
    /** Implements the `Type` interface. */
    auto _isResolved(ResolvedState* rstate) const { return true; }
    /** Implements the `Type` interface. */
    const Type& elementType() const { return child<Type>(0); }

    /** Implements the `Type` interface. */
    const Type& iteratorType(bool /* const */) const { return child<Type>(1); }
    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }
};

} // namespace hilti::type
