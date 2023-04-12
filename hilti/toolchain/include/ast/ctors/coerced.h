// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/ctor.h>
#include <hilti/ast/type.h>

namespace hilti::ctor {

/** AST node for a constructor that's been coerced from one type to another. */
class Coerced : public NodeBase, public hilti::trait::isCtor {
public:
    Coerced(Ctor orig, Ctor new_, Meta m = Meta()) : NodeBase({std::move(orig), std::move(new_)}, std::move(m)) {}

    const auto& originalCtor() const { return child<Ctor>(0); }
    const auto& coercedCtor() const { return child<Ctor>(1); }

    bool operator==(const Coerced& other) const {
        return originalCtor() == other.originalCtor() && coercedCtor() == other.coercedCtor();
    }

    /** Implements `Ctor` interface. */
    const Type& type() const { return coercedCtor().type(); }
    /** Implements `Ctor` interface. */
    bool isConstant() const { return coercedCtor().isConstant(); }
    /** Implements `Ctor` interface. */
    auto isLhs() const { return coercedCtor().isLhs(); }
    /** Implements `Ctor` interface. */
    auto isTemporary() const { return coercedCtor().isTemporary(); }
    /** Implements `Ctor` interface. */
    auto isEqual(const Ctor& other) const { return node::isEqual(this, other); }

    /** Implements `Node` interface. */
    auto properties() const { return node::Properties{}; }
};

} // namespace hilti::ctor
