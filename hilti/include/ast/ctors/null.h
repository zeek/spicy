// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/ctor.h>
#include <hilti/ast/types/null.h>

namespace hilti {
namespace ctor {

/** AST node for a null constructor. */
class Null : public NodeBase, public hilti::trait::isCtor {
public:
    Null(Meta m = Meta()) : NodeBase(std::move(m)) {}

    bool operator==(const Null& /* other */) const { return true; }

    /** Implements `Ctor` interface. */
    auto type() const { return type::Null(); }
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

} // namespace ctor
} // namespace hilti
