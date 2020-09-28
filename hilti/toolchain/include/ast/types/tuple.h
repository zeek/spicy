// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>
#include <vector>

#include <hilti/ast/id.h>
#include <hilti/ast/type.h>

namespace hilti {
namespace type {

/** AST node for a tuple type. */
class Tuple : public TypeBase, trait::isAllocable, trait::isParameterized {
public:
    Tuple(std::vector<Type> t, Meta m = Meta()) : TypeBase(nodes(std::move(t)), std::move(m)) {}
    Tuple(std::vector<std::pair<ID, Type>> t, Meta m = Meta()) : TypeBase(nodes(std::move(t)), std::move(m)) {}
    Tuple(Wildcard /*unused*/, Meta m = Meta()) : TypeBase(std::move(m)), _wildcard(true) {}

    auto types() const { return childsOfType<Type>(); }
    std::vector<ID> ids() const;
    auto elements() const { return util::zip2(ids(), types()); }
    std::optional<std::pair<int, Type>> elementByID(const ID& id);

    bool operator==(const Tuple& other) const {
        if ( _wildcard || other._wildcard )
            return _wildcard && other._wildcard;

        return types() == other.types() && ids() == other.ids();
    }

    /** Implements the `Type` interface. */
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }
    /** Implements the `Type` interface. */
    auto typeParameters() const { return childs(); }
    /** Implements the `Type` interface. */
    auto isWildcard() const { return _wildcard; }

    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{{"wildcard", _wildcard}}; }

private:
    bool _wildcard = false;
};

} // namespace type
} // namespace hilti
