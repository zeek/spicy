// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/type.h>
#include <hilti/ast/types/integer.h>
#include <hilti/base/optional-ref.h>

namespace hilti::type {

namespace stream {

/** AST node for a stream iterator type. */
class Iterator : public TypeBase {
public:
    Iterator(Meta m = Meta()) : TypeBase(nodes(type::UnsignedInteger(8)), std::move(m)) {}

    bool operator==(const Iterator& /* other */) const { return true; }

    bool isEqual(const Type& other) const override { return node::isEqual(this, other); }
    bool _isResolved(ResolvedState* rstate) const override { return true; }
    optional_ref<const Type> dereferencedType() const override { return child<Type>(0); }
    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }

    bool _isAllocable() const override { return true; }
    bool _isIterator() const override { return true; }
    bool _isMutable() const override { return true; }
    bool _isRuntimeNonTrivial() const override { return true; }
};

/** AST node for a stream view type. */
class View : public TypeBase {
public:
    View(const Meta& m = Meta()) : TypeBase(nodes(stream::Iterator(m)), m) {}

    bool operator==(const View& /* other */) const { return true; }

    bool isEqual(const Type& other) const override { return node::isEqual(this, other); }
    bool _isResolved(ResolvedState* rstate) const override { return true; }
    optional_ref<const Type> elementType() const override { return iteratorType(true)->dereferencedType(); }
    optional_ref<const Type> iteratorType(bool /* const_ */) const override { return child<Type>(0); }
    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }

    bool _isAllocable() const override { return true; }
    bool _isRuntimeNonTrivial() const override { return true; }
};

} // namespace stream

/** AST node for a stream type. */
class Stream : public TypeBase {
public:
    Stream(const Meta& m = Meta()) : TypeBase(nodes(stream::View(m)), m) {}

    bool operator==(const Stream& /* other */) const { return true; }

    bool isEqual(const Type& other) const override { return node::isEqual(this, other); }
    bool _isResolved(ResolvedState* rstate) const override { return true; }
    optional_ref<const Type> elementType() const override { return iteratorType(true)->dereferencedType(); }
    optional_ref<const Type> iteratorType(bool /* const_ */) const override { return viewType()->iteratorType(true); }
    optional_ref<const Type> viewType() const override { return child<Type>(0); }
    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }

    bool _isAllocable() const override { return true; }
    bool _isMutable() const override { return true; }
    bool _isRuntimeNonTrivial() const override { return true; }
};

namespace detail::stream {
inline Node element_type = Node(type::UnsignedInteger(8, Location()));
} // namespace detail::stream

} // namespace hilti::type
