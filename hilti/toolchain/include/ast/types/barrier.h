// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>
#include <vector>

#include <hilti/ast/ctors/integer.h>
#include <hilti/ast/type.h>

namespace hilti::type {

/** AST node for a `barrier` type. */
class Barrier : public TypeBase, trait::isAllocable, trait::isParameterized {
public:
    Barrier(uint64_t expected_parties, Meta m = Meta()) : TypeBase(std::move(m)), _parties(expected_parties) {}
    Barrier(Wildcard /*unused*/, Meta m = Meta()) : TypeBase(std::move(m)), _wildcard(true) {}

    auto parties() const { return _parties; }

    bool operator==(const Barrier& other) const { return parties() == other.parties(); }

    /** Implements the `Type` interface. */
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }
    /** Implements the `Type` interface. */
    auto _isResolved(ResolvedState* rstate) const { return true; }
    /** Implements the `Type` interface. */
    auto isWildcard() const { return _wildcard; }
    /** Implements the `Type` interface. */
    std::vector<Node> typeParameters() const { return {Ctor(ctor::UnsignedInteger(parties(), 64))}; }

    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{{"parties", _parties}}; }

private:
    uint64_t _parties = 0; // number of parties expected to arrive at the barrier
    bool _wildcard = false;
};

} // namespace hilti::type
