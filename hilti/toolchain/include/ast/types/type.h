// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/type.h>
#include <hilti/ast/types/any.h>

namespace hilti {
namespace type {

/** AST node for a type representing a type value. */
class Type_ : public TypeBase, trait::isParameterized {
public:
    Type_(Type t, Meta m = Meta()) : TypeBase({std::move(t)}, std::move(m)) {}
    Type_(Wildcard /*unused*/, Meta m = Meta()) : TypeBase(std::move(m)), _wildcard(true) {}

    auto typeValue() const { return _wildcard ? type::Any() : type::effectiveType(child<Type>(0)); }

    bool operator==(const Type_& other) const { return typeValue() == other.typeValue(); }

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
