// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>
#include <vector>

#include <hilti/ast/type.h>

namespace hilti::type {

/** AST node for an `exception` type. */
class Exception : public TypeBase {
public:
    Exception(Meta m = Meta()) : TypeBase({node::none}, std::move(m)) {}
    Exception(Type base, Meta m = Meta()) : TypeBase({std::move(base)}, std::move(m)) {}
    Exception(Wildcard /*unused*/, Meta m = Meta()) : TypeBase({node::none}, std::move(m)), _wildcard(true) {}

    hilti::optional_ref<const Type> baseType() const { return children()[0].tryAs<Type>(); }

    bool operator==(const Exception& other) const { return baseType() == other.baseType(); }

    bool isEqual(const Type& other) const override { return node::isEqual(this, other); }

    bool _isResolved(ResolvedState* rstate) const override {
        return baseType().has_value() ? type::detail::isResolved(baseType(), rstate) : true;
    }

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
