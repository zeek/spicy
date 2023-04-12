// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/type.h>

namespace hilti::type {

/** AST node for a floating point type. */
class Real : public TypeBase, trait::isAllocable, trait::isSortable {
public:
    Real(Meta m = Meta()) : TypeBase(std::move(m)) {}

    bool operator==(const Real& /* other */) const { return true; }

    /** Implements the `Type` interface. */
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }
    /** Implements the `Type` interface. */
    auto _isResolved(ResolvedState* rstate) const { return true; }

    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }
};

} // namespace hilti::type
