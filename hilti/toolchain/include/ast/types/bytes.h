// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/type.h>
#include <hilti/ast/types/integer.h>
#include <hilti/base/optional-ref.h>

namespace hilti::type {

namespace bytes {

/** AST node for a list iterator type. */
class Iterator : public TypeBase {
public:
    Iterator(Meta m = Meta()) : TypeBase(nodes(Type(type::UnsignedInteger(8))), std::move(m)) {}

    bool operator==(const Iterator& /* other */) const { return true; }

    bool isEqual(const Type& other) const override { return node::isEqual(this, other); }
    bool _isResolved(ResolvedState* rstate) const override { return true; }
    /** Implements the `Type` interface. */
    optional_ref<const Type> dereferencedType() const override { return child<Type>(0); }
    node::Properties properties() const override { return node::Properties{}; }

    bool _isAllocable() const override { return true; }
    bool _isIterator() const override { return true; }
    bool _isMutable() const override { return true; }
    bool _isRuntimeNonTrivial() const override { return true; }
};

} // namespace bytes

/** AST node for a bytes type. */
class Bytes : public TypeBase {
public:
    Bytes(const Meta& m = Meta()) : TypeBase(nodes(Type(type::UnsignedInteger(8)), Type(bytes::Iterator(m))), m) {}

    bool operator==(const Bytes& /* other */) const { return true; }

    bool isEqual(const Type& other) const override { return node::isEqual(this, other); }
    bool _isResolved(ResolvedState* rstate) const override { return true; }
    optional_ref<const Type> elementType() const override { return child<Type>(0); }

    optional_ref<const Type> iteratorType(bool /* const */) const override { return child<Type>(1); }

    node::Properties properties() const override { return node::Properties{}; }

    bool _isAllocable() const override { return true; }
    bool _isMutable() const override { return true; }
    bool _isRuntimeNonTrivial() const override { return true; }
    bool _isSortable() const override { return true; }
};

} // namespace hilti::type
