// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/type.h>
#include <hilti/ast/types/tuple.h>
#include <hilti/ast/types/unknown.h>

namespace hilti::type {

namespace map {

/** AST node for a map iterator type. */
class Iterator : public TypeBase,
                 trait::isIterator,
                 trait::isDereferenceable,
                 trait::isAllocable,
                 trait::isMutable,
                 trait::isRuntimeNonTrivial,
                 trait::isParameterized {
public:
    Iterator(Type ktype, Type vtype, bool const_, const Meta& m = Meta())
        : TypeBase(nodes(type::Tuple({std::move(ktype), std::move(vtype)}, m)), m), _const(const_) {}
    Iterator(Wildcard /*unused*/, bool const_ = true, Meta m = Meta())
        : TypeBase(nodes(type::unknown, type::unknown), std::move(m)), _wildcard(true), _const(const_) {}

    const Type& keyType() const {
        if ( auto t = children()[0].tryAs<type::Tuple>() )
            return t->elements()[0].type();
        else
            return child<Type>(0);
    }

    const Type& valueType() const {
        if ( auto t = children()[0].tryAs<type::Tuple>() )
            return t->elements()[1].type();
        else
            return child<Type>(0);
    }

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

    bool operator==(const Iterator& other) const {
        return keyType() == other.keyType() && valueType() == other.valueType();
    }

private:
    bool _wildcard = false;
    bool _const = false;
};

} // namespace map

/** AST node for a map type. */
class Map : public TypeBase,
            trait::isAllocable,
            trait::isMutable,
            trait::isIterable,
            trait::isRuntimeNonTrivial,
            trait::isParameterized {
public:
    Map(const Type& k, const Type& v, const Meta& m = Meta())
        : TypeBase(nodes(map::Iterator(k, v, true, m), map::Iterator(k, v, false, m)), m) {}
    Map(Wildcard /*unused*/, const Meta& m = Meta())
        : TypeBase(nodes(map::Iterator(Wildcard{}, true, m), map::Iterator(Wildcard{}, false, m)), m),
          _wildcard(true) {}

    const Type& keyType() const { return child<map::Iterator>(0).keyType(); }
    const Type& valueType() const { return child<map::Iterator>(0).valueType(); }

    /** Implements the `Type` interface. */
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }
    /** Implements the `Type` interface. */
    auto _isResolved(ResolvedState* rstate) const {
        return type::detail::isResolved(iteratorType(true), rstate) &&
               type::detail::isResolved(iteratorType(false), rstate);
    }
    /** Implements the `Type` interface. */
    const Type& elementType() const { return valueType(); }
    /** Implements the `Type` interface. */
    const Type& iteratorType(bool const_) const { return const_ ? child<Type>(0) : child<Type>(1); }
    /** Implements the `Type` interface. */
    auto isWildcard() const { return _wildcard; }
    /** Implements the `Type` interface. */
    auto typeParameters() const { return children(); }
    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }

    bool operator==(const Map& other) const { return iteratorType(true) == other.iteratorType(true); }

private:
    bool _wildcard = false;
};

} // namespace hilti::type
