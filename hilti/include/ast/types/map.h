// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/type.h>
#include <hilti/ast/types/tuple.h>
#include <hilti/ast/types/unknown.h>

namespace hilti {
namespace type {

namespace map {

/** AST node for a map iterator type. */
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
    Type dereferencedType() const;
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

} // namespace map

/** AST node for a map type. */
class Map : public TypeBase,
            trait::isAllocable,
            trait::isMutable,
            trait::isIterable,
            trait::isRuntimeNonTrivial,
            trait::isParameterized {
public:
    Map(Type key, Type value, Meta m = Meta()) : TypeBase({std::move(key), std::move(value)}, std::move(m)) {}
    Map(Wildcard /*unused*/, Meta m = Meta()) : TypeBase({node::none}, std::move(m)), _wildcard(true) {}

    Type keyType() const { return _wildcard ? type::unknown : type::effectiveType(child<Type>(0)); }

    /** Implements the `Type` interface. */
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }
    /** Implements the `Type` interface. */
    Type elementType() const { return _wildcard ? type::unknown : type::effectiveType(child<Type>(1)); }
    /** Implements the `Type` interface. */
    Type iteratorType(bool const_) const { return map::Iterator(*this, const_, meta()); }
    /** Implements the `Type` interface. */
    auto isWildcard() const { return _wildcard; }
    /** Implements the `Type` interface. */
    auto typeParameters() const { return childs(); }
    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }

    bool operator==(const Map& other) const {
        return keyType() == other.keyType() && elementType() == other.elementType();
    }

private:
    bool _wildcard = false;
};

namespace map {
inline Type Iterator::dereferencedType() const {
    if ( _wildcard || containerType().isWildcard() )
        return type::unknown;

    return type::Tuple({containerType().as<type::Map>().keyType(), containerType().elementType()});
}
} // namespace map

} // namespace type
} // namespace hilti
