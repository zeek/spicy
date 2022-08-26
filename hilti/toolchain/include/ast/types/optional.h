// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>
#include <vector>

#include <hilti/ast/type.h>
#include <hilti/ast/types/unknown.h>
#include <hilti/base/optional-ref.h>

namespace hilti::type {

/** AST node for an "optional" type. */
class Optional : public TypeBase {
public:
    Optional(Wildcard /*unused*/, Meta m = Meta()) : TypeBase({type::unknown}, std::move(m)), _wildcard(true) {}
    Optional(Type ct, Meta m = Meta()) : TypeBase({std::move(ct)}, std::move(m)) {}

    optional_ref<const Type> dereferencedType() const override { return children()[0].as<Type>(); }

    bool operator==(const Optional& other) const { return dereferencedType() == other.dereferencedType(); }

    /** Implements the `Type` interface. */
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }
    /** Implements the `Type` interface. */
    auto _isResolved(ResolvedState* rstate) const { return type::detail::isResolved(dereferencedType(), rstate); }
    /** Implements the `Type` interface. */
    std::vector<Node> typeParameters() const override { return children(); }
    /** Implements the `Type` interface. */
    bool isWildcard() const override { return _wildcard; }

    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }

    bool _isAllocable() const override { return true; }
    bool _isParameterized() const override { return true; }

private:
    bool _wildcard = false;
};

} // namespace hilti::type
