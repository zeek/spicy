// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/type.h>
#include <hilti/ast/types/unknown.h>

namespace hilti::type {

/*
 * AST node for a `strong_ref<T>` type.
 */
class StrongReference : public TypeBase,
                        trait::isAllocable,
                        trait::isParameterized,
                        trait::isDereferenceable,
                        trait::isReferenceType {
public:
    StrongReference(Wildcard /*unused*/, Meta m = Meta()) : TypeBase({type::unknown}, std::move(m)), _wildcard(true) {}
    StrongReference(Type ct, Meta m = Meta()) : TypeBase(nodes(std::move(ct)), std::move(m)) {}
    StrongReference(NodeRef ct, Meta m = Meta()) : TypeBase(nodes(node::none), std::move(m)), _type(std::move(ct)) {}

    const Type& dereferencedType() const {
        if ( _type )
            return _type->as<Type>();
        else
            return children()[0].as<Type>();
    }

    bool operator==(const StrongReference& other) const { return dereferencedType() == other.dereferencedType(); }

    /** Implements the `Type` interface. */
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }
    /** Implements the `Type` interface. */
    auto _isResolved(ResolvedState* rstate) const { return type::detail::isResolved(dereferencedType(), rstate); }
    /** Implements the `Type` interface. */
    auto typeParameters() const { return children(); }
    /** Implements the `Type` interface. */
    auto isWildcard() const { return _wildcard; }

    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{{"type", _type.renderedRid()}}; }

private:
    bool _wildcard = false;
    NodeRef _type;
};

/** AST node for a `weak_ref<T>` type. */
class WeakReference : public TypeBase,
                      trait::isAllocable,
                      trait::isParameterized,
                      trait::isDereferenceable,
                      trait::isReferenceType {
public:
    WeakReference(Wildcard /*unused*/, Meta m = Meta()) : TypeBase({type::unknown}, std::move(m)), _wildcard(true) {}
    WeakReference(Type ct, Meta m = Meta()) : TypeBase({std::move(ct)}, std::move(m)) {}

    const Type& dereferencedType() const { return children()[0].as<Type>(); }

    bool operator==(const WeakReference& other) const { return dereferencedType() == other.dereferencedType(); }

    /** Implements the `Type` interface. */
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }
    /** Implements the `Type` interface. */
    auto _isResolved(ResolvedState* rstate) const { return type::detail::isResolved(dereferencedType(), rstate); }
    /** Implements the `Type` interface. */
    auto typeParameters() const { return children(); }
    /** Implements the `Type` interface. */
    auto isWildcard() const { return _wildcard; }

    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }

private:
    bool _wildcard = false;
};

/** AST node for a `val_ref<T>` type. */
class ValueReference : public TypeBase,
                       trait::isAllocable,
                       trait::isParameterized,
                       trait::isDereferenceable,
                       trait::isReferenceType {
public:
    ValueReference(Wildcard /*unused*/, Meta m = Meta())
        : TypeBase(nodes(type::unknown), std::move(m)), _wildcard(true) {}
    ValueReference(Type ct, Meta m = Meta()) : TypeBase(nodes(std::move(ct)), std::move(m)) {}
    ValueReference(NodeRef ct, Meta m = Meta()) : TypeBase(nodes(type::unknown), std::move(m)), _node(std::move(ct)) {}

    const Type& dereferencedType() const {
        if ( _node )
            return _node->as<Type>();
        else
            return children()[0].as<Type>();
    }

    bool operator==(const ValueReference& other) const { return dereferencedType() == other.dereferencedType(); }

    /** Implements the `Type` interface. */
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }
    /** Implements the `Type` interface. */
    auto _isResolved(ResolvedState* rstate) const { return type::detail::isResolved(dereferencedType(), rstate); }
    /** Implements the `Type` interface. */
    auto typeParameters() const { return children(); }
    /** Implements the `Type` interface. */
    auto isWildcard() const { return _wildcard; }

    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{{"rid", (_node ? _node->rid() : 0U)}}; }

private:
    bool _wildcard = false;
    NodeRef _node;
};

} // namespace hilti::type
