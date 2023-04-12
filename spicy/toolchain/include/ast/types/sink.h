// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/type.h>

namespace spicy::type {

/** AST node for a Sink type. */
class Sink : public hilti::TypeBase, hilti::type::trait::isAllocable {
public:
    Sink(hilti::Meta m = hilti::Meta()) : TypeBase(std::move(m)) {}

    bool operator==(const Sink& /* other */) const { return true; }

    /** Implements the `Type` interface. */
    auto isEqual(const hilti::Type& other) const { return hilti::node::isEqual(this, other); }
    /** Implements the `Type` interface. */
    auto _isResolved(hilti::type::ResolvedState* rstate) const { return true; }
    /** Implements the `Node` interface. */
    auto properties() const { return hilti::node::Properties{}; }
};

} // namespace spicy::type
