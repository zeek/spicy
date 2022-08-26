// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>
#include <vector>

#include <hilti/ast/type.h>
#include <hilti/ast/types/tuple.h>
#include <hilti/ast/types/unknown.h>
#include <hilti/base/optional-ref.h>

namespace hilti::type {

namespace map {

/** AST node for a map iterator type. */
class Iterator : public TypeBase, trait::isIterator {
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
    optional_ref<const Type> dereferencedType() const override { return child<Type>(0); }
    /** Implements the `Type` interface. */
    bool isWildcard() const override { return _wildcard; }
    /** Implements the `Type` interface. */
    std::vector<Node> typeParameters() const override { return children(); }
    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{{"const", _const}}; }

    bool _isAllocable() const override { return true; }
    bool _isMutable() const override { return true; }
    bool _isParameterized() const override { return true; }
    bool _isRuntimeNonTrivial() const override { return true; }

    bool operator==(const Iterator& other) const {
        return keyType() == other.keyType() && valueType() == other.valueType();
    }

private:
    bool _wildcard = false;
    bool _const = false;
};

} // namespace map

/** AST node for a map type. */
class Map : public TypeBase {
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
    bool isWildcard() const override { return _wildcard; }
    std::vector<Node> typeParameters() const override { return children(); }
    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }

    bool _isAllocable() const override { return true; }
    bool _isIterable() const override { return true; }
    bool _isMutable() const override { return true; }
    bool _isParameterized() const override { return true; }
    bool _isRuntimeNonTrivial() const override { return true; }

    bool operator==(const Map& other) const { return iteratorType(true) == other.iteratorType(true); }

private:
    bool _wildcard = false;
};

} // namespace hilti::type
