// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>
#include <vector>

#include <hilti/ast/id.h>
#include <hilti/ast/node-ref.h>
#include <hilti/ast/type.h>

namespace hilti::type {

/** AST node for a type representing a member of another type. */
class Member : public TypeBase {
public:
    Member(Wildcard /*unused*/, Meta m = Meta()) : TypeBase({ID("<wildcard>")}, std::move(m)), _wildcard(true) {}
    Member(::hilti::ID id, Meta m = Meta()) : TypeBase({std::move(id)}, std::move(m)) {}

    const auto& id() const { return child<::hilti::ID>(0); }

    bool operator==(const Member& other) const { return id() == other.id(); }

    bool isEqual(const Type& other) const override { return node::isEqual(this, other); }
    bool _isResolved(ResolvedState* rstate) const override { return true; }
    std::vector<Node> typeParameters() const override { return std::vector<Node>{id()}; }
    bool isWildcard() const override { return _wildcard; }

    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }

    bool _isParameterized() const override { return true; }

private:
    bool _wildcard = false;
};

} // namespace hilti::type
