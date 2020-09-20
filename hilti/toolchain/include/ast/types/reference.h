// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/type.h>
#include <hilti/ast/types/unknown.h>

namespace hilti {
namespace type {

/*
 * AST node for a `strong_ref<T>` type.
 */
class StrongReference : public TypeBase,
                        trait::isAllocable,
                        trait::isParameterized,
                        trait::isDereferencable,
                        trait::isReferenceType {
public:
    StrongReference(Wildcard /*unused*/, Meta m = Meta()) : TypeBase({node::none}, std::move(m)), _wildcard(true) {}
    StrongReference(Type ct, Meta m = Meta()) : TypeBase({std::move(ct)}, std::move(m)) {}
    StrongReference(Type ct, bool treat_as_non_constant, Meta m = Meta()) : TypeBase({std::move(ct)}, std::move(m)) {
        if ( treat_as_non_constant )
            _state().flags -= type::Flag::Constant;
    }

    Type dereferencedType() const {
        if ( auto t = childs()[0].tryAs<Type>() )
            return type::effectiveType(*t);

        return type::unknown;
    }

    bool operator==(const StrongReference& other) const { return dereferencedType() == other.dereferencedType(); }

    /** Implements the `Type` interface. */
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }
    /** Implements the `Type` interface. */
    auto typeParameters() const { return childs(); }
    /** Implements the `Type` interface. */
    auto isWildcard() const { return _wildcard; }

    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }

private:
    bool _wildcard = false;
};

/** AST node for a `weak_ref<T>` type. */
class WeakReference : public TypeBase,
                      trait::isAllocable,
                      trait::isParameterized,
                      trait::isDereferencable,
                      trait::isReferenceType {
public:
    WeakReference(Wildcard /*unused*/, Meta m = Meta()) : TypeBase({node::none}, std::move(m)), _wildcard(true) {}
    WeakReference(Type ct, Meta m = Meta()) : TypeBase({std::move(ct)}, std::move(m)) {}

    Type dereferencedType() const {
        if ( auto t = childs()[0].tryAs<Type>() )
            return type::effectiveType(*t);

        return type::unknown;
    }

    bool operator==(const WeakReference& other) const { return dereferencedType() == other.dereferencedType(); }

    /** Implements the `Type` interface. */
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }
    /** Implements the `Type` interface. */
    auto typeParameters() const { return childs(); }
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
                       trait::isDereferencable,
                       trait::isReferenceType {
public:
    ValueReference(Wildcard /*unused*/, Meta m = Meta()) : TypeBase({node::none}, std::move(m)), _wildcard(true) {}
    ValueReference(Type ct, Meta m = Meta()) : TypeBase({std::move(ct)}, std::move(m)) {}

    Type dereferencedType() const {
        if ( auto t = childs()[0].tryAs<Type>() )
            return type::effectiveType(*t);

        return type::unknown;
    }

    bool operator==(const ValueReference& other) const { return dereferencedType() == other.dereferencedType(); }

    /** Implements the `Type` interface. */
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }
    /** Implements the `Type` interface. */
    auto typeParameters() const { return childs(); }
    /** Implements the `Type` interface. */
    auto isWildcard() const { return _wildcard; }

    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }

private:
    bool _wildcard = false;
};

} // namespace type
} // namespace hilti
