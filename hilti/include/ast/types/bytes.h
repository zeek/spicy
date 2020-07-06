// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/type.h>
#include <hilti/ast/types/integer.h>

namespace hilti {
namespace type {

namespace bytes {

/** AST node for a list iterator type. */
class Iterator : public TypeBase,
                 trait::isIterator,
                 trait::isDereferencable,
                 trait::isAllocable,
                 trait::isMutable,
                 trait::isRuntimeNonTrivial {
public:
    Iterator(Meta m = Meta()) : TypeBase(std::move(m)) {}

    bool operator==(const Iterator& /* other */) const { return true; }

    /** Implements the `Type` interface. */
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }
    /** Implements the `Type` interface. */
    Type dereferencedType() const;
    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }
};

} // namespace bytes

/** AST node for a bytes type. */
class Bytes : public TypeBase, trait::isAllocable, trait::isMutable, trait::isIterable, trait::isRuntimeNonTrivial {
public:
    Bytes(Meta m = Meta()) : TypeBase(std::move(m)) {}

    bool operator==(const Bytes& /* other */) const { return true; }

    /** Implements the `Type` interface. */
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }
    /** Implements the `Type` interface. */
    Type elementType() const { return type::UnsignedInteger(8); }

    /** Implements the `Type` interface. */
    Type iteratorType(bool /* const_ */) const { return bytes::Iterator(meta()); }
    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }

private:
    std::optional<Node> _etype;
};

namespace detail::bytes {
inline Node element_type = Node(type::UnsignedInteger(8, Location()));
} // namespace detail::bytes

inline Type bytes::Iterator::dereferencedType() const { return type::UnsignedInteger(8); }

} // namespace type

} // namespace hilti
