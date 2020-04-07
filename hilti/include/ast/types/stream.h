// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/type.h>
#include <hilti/ast/types/integer.h>

namespace hilti {
namespace type {

namespace stream {

/** AST node for a stream iterator type. */
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

/** AST node for a stream view type. */
class View : public TypeBase, trait::isView, trait::isIterable, trait::isAllocable, trait::isRuntimeNonTrivial {
public:
    View(Meta m = Meta());

    bool operator==(const View& /* other */) const { return true; }

    /** Implements the `Type` interface. */
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }
    /** Implements the `Type` interface. */
    Type elementType() const { return type::UnsignedInteger(8); }
    /** Implements the `Type` interface. */
    Type iteratorType(bool /* const_ */) const { return stream::Iterator(meta()); }
    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }
};

} // namespace stream

/** AST node for a stream type. */
class Stream : public TypeBase,
               trait::isAllocable,
               trait::isMutable,
               trait::isIterable,
               trait::isViewable,
               trait::isRuntimeNonTrivial {
public:
    Stream(Meta m = Meta()) : TypeBase(std::move(m)) {}

    bool operator==(const Stream& /* other */) const { return true; }

    /** Implements the `Type` interface. */
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }
    /** Implements the `Type` interface. */
    Type elementType() const { return type::UnsignedInteger(8); }

    /** Implements the `Type` interface. */
    Type iteratorType(bool /* const_ */) const { return stream::Iterator(meta()); }
    /** Implements the `Type` interface. */
    Type viewType() const { return stream::View(meta()); }
    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }

private:
    std::optional<Node> _etype;
};

namespace detail::stream {
inline Node element_type = Node(type::UnsignedInteger(8, Location()));
} // namespace detail::stream

inline Type stream::Iterator::dereferencedType() const { return type::UnsignedInteger(8); }
inline stream::View::View(Meta m) : TypeBase({type::Stream()}, std::move(m)) {}

} // namespace type

} // namespace hilti
