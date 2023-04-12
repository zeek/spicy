// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/type.h>
#include <hilti/ast/types/any.h>

namespace hilti::type {

/** AST node for a type representing a type value. */
class Type_ : public TypeBase, trait::isParameterized {
public:
    Type_(Type t, Meta m = Meta()) : TypeBase(nodes(std::move(t)), std::move(m)) {}
    Type_(Wildcard /*unused*/, Meta m = Meta()) : TypeBase(nodes(type::Any()), std::move(m)), _wildcard(true) {}

    const auto& typeValue() const { return child<Type>(0); }

    bool operator==(const Type_& other) const { return typeValue() == other.typeValue(); }

    /** Implements the `Type` interface. */
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }
    /** Implements the `Type` interface. */
    auto _isResolved(ResolvedState* rstate) const { return type::detail::isResolved(typeValue(), rstate); }
    /** Implements the `Type` interface. */
    auto typeParameters() const { return children(); }
    /** Implements the `Type` interface. */
    auto isWildcard() const { return _wildcard; }
    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }

private:
    bool _wildcard = false;
};

} // namespace hilti::type
