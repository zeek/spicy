// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/type.h>

namespace spicy {
namespace type {

/** AST node for a Sink type. */
class Sink : public hilti::TypeBase, hilti::type::trait::isAllocable {
public:
    Sink(Meta m = Meta()) : TypeBase(std::move(m)) {}

    bool operator==(const Sink& /* other */) const { return true; }

    /** Implements the `Type` interface. */
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }
    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }
};

} // namespace type
} // namespace spicy
