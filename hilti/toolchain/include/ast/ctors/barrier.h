// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/ctor.h>
#include <hilti/ast/types/barrier.h>

namespace hilti::ctor {

/** AST node for a barrier constructor. */
class Barrier : public NodeBase, public hilti::trait::isCtor {
public:
    Barrier(uint64_t parties, const Meta& m = Meta()) : NodeBase(nodes(type::Barrier(parties, m)), m) {}
    Barrier(const Meta& m = Meta()) : NodeBase(nodes(type::Barrier(type::Wildcard(), m)), m) {}

    bool operator==(const Barrier& other) const { return false; }

    /** Implements `Ctor` interface. */
    const Type& type() const { return child<Type>(0); }
    /** Implements `Ctor` interface. */
    bool isConstant() const { return true; }
    /** Implements `Ctor` interface. */
    auto isLhs() const { return false; }
    /** Implements `Ctor` interface. */
    auto isTemporary() const { return true; }
    /** Implements `Ctor` interface. */
    auto isEqual(const Ctor& other) const { return node::isEqual(this, other); }

    /** Implements `Node` interface. */
    auto properties() const { return node::Properties{}; }
};

} // namespace hilti::ctor
