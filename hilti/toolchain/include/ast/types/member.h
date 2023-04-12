// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>
#include <vector>

#include <hilti/ast/id.h>
#include <hilti/ast/node-ref.h>
#include <hilti/ast/type.h>

namespace hilti::type {

/** AST node for a type representing a member of another type. */
class Member : public TypeBase, trait::isParameterized {
public:
    Member(Wildcard /*unused*/, Meta m = Meta()) : TypeBase({ID("<wildcard>")}, std::move(m)), _wildcard(true) {}
    Member(::hilti::ID id, Meta m = Meta()) : TypeBase({std::move(id)}, std::move(m)) {}

    const auto& id() const { return child<::hilti::ID>(0); }

    bool operator==(const Member& other) const { return id() == other.id(); }

    /** Implements the `Type` interface. */
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }
    /** Implements the `Type` interface. */
    auto _isResolved(ResolvedState* rstate) const { return true; }
    /** Implements the `Type` interface. */
    auto typeParameters() const { return std::vector<Node>{id()}; }
    /** Implements the `Type` interface. */
    auto isWildcard() const { return _wildcard; }

    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }

private:
    bool _wildcard = false;
};

} // namespace hilti::type
