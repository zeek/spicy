// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/type.h>
#include <hilti/ast/types/integer.h>
#include <hilti/base/optional-ref.h>

namespace hilti::type {

namespace stream {

/** AST node for a stream iterator type. */
class Iterator : public TypeBase, trait::isIterator {
public:
    Iterator(Meta m = Meta()) : TypeBase(nodes(type::UnsignedInteger(8)), std::move(m)) {}

    bool operator==(const Iterator& /* other */) const { return true; }

    /** Implements the `Type` interface. */
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }
    /** Implements the `Type` interface. */
    auto _isResolved(ResolvedState* rstate) const { return true; }
    optional_ref<const Type> dereferencedType() const override { return child<Type>(0); }
    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }

    bool _isAllocable() const override { return true; }
    bool _isMutable() const override { return true; }
    bool _isRuntimeNonTrivial() const override { return true; }
};

/** AST node for a stream view type. */
class View : public TypeBase {
public:
    View(const Meta& m = Meta()) : TypeBase(nodes(stream::Iterator(m)), m) {}

    bool operator==(const View& /* other */) const { return true; }

    /** Implements the `Type` interface. */
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }
    /** Implements the `Type` interface. */
    auto _isResolved(ResolvedState* rstate) const { return true; }
    optional_ref<const Type> elementType() const override { return iteratorType(true)->dereferencedType(); }
    optional_ref<const Type> iteratorType(bool /* const_ */) const override { return child<Type>(0); }
    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }

    bool _isAllocable() const override { return true; }
    bool _isRuntimeNonTrivial() const override { return true; }
};

} // namespace stream

/** AST node for a stream type. */
class Stream : public TypeBase, trait::isViewable {
public:
    Stream(const Meta& m = Meta()) : TypeBase(nodes(stream::View(m)), m) {}

    bool operator==(const Stream& /* other */) const { return true; }

    /** Implements the `Type` interface. */
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }
    /** Implements the `Type` interface. */
    auto _isResolved(ResolvedState* rstate) const { return true; }
    optional_ref<const Type> elementType() const override { return iteratorType(true)->dereferencedType(); }
    optional_ref<const Type> iteratorType(bool /* const_ */) const override { return viewType().iteratorType(true); }
    /** Implements the `Type` interface. */
    const Type& viewType() const { return child<Type>(0); }
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
