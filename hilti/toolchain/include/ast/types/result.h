// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>
#include <vector>

#include <hilti/ast/type.h>
#include <hilti/ast/types/unknown.h>

namespace hilti::type {

/** AST node for a "result" type. */
class Result : public TypeBase, trait::isDereferenceable {
public:
    Result(Wildcard /*unused*/, Meta m = Meta()) : TypeBase({type::unknown}, std::move(m)), _wildcard(true) {}
    Result(Type ct, Meta m = Meta()) : TypeBase({std::move(ct)}, std::move(m)) {}

    const Type& dereferencedType() const { return children()[0].as<Type>(); }

    bool operator==(const Result& other) const { return dereferencedType() == other.dereferencedType(); }

    /** Implements the `Type` interface. */
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }
    /** Implements the `Type` interface. */
    auto _isResolved(ResolvedState* rstate) const { return type::detail::isResolved(dereferencedType(), rstate); }
    std::vector<Node> typeParameters() const override { return children(); }
    bool isWildcard() const override { return _wildcard; }

    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }

    bool _isAllocable() const override { return true; }
    bool _isParameterized() const override { return true; }

private:
    bool _wildcard = false;
};

} // namespace hilti::type
