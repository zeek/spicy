// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/type.h>

namespace hilti {
namespace type {

/** AST node for an "optional" type. */
class Optional : public TypeBase, trait::isAllocable, trait::isParameterized, trait::isDereferencable {
public:
    Optional(Wildcard /*unused*/, Meta m = Meta()) : TypeBase({node::none}, std::move(m)), _wildcard(true) {}
    Optional(Type ct, Meta m = Meta()) : TypeBase({std::move(ct)}, std::move(m)) {}

    Type dereferencedType() const {
        if ( auto t = childs()[0].tryAs<Type>() )
            return *t;

        return type::unknown;
    }

    bool operator==(const Optional& other) const { return dereferencedType() == other.dereferencedType(); }

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
