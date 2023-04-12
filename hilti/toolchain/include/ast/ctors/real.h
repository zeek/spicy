// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/ctor.h>
#include <hilti/ast/types/real.h>

namespace hilti::ctor {

/** AST node for a double precision floating-point constructor. */
class Real : public NodeBase, public hilti::trait::isCtor {
public:
    Real(double v, const Meta& m = Meta()) : NodeBase(nodes(type::Real(m)), m), _value(v) {}

    auto value() const { return _value; }

    bool operator==(const Real& other) const { return value() == other.value(); }

    /** Implements `Ctor` interface. */
    const auto& type() const { return child<Type>(0); }
    /** Implements `Ctor` interface. */
    bool isConstant() const { return true; }
    /** Implements `Ctor` interface. */
    auto isLhs() const { return false; }
    /** Implements `Ctor` interface. */
    auto isTemporary() const { return true; }
    /** Implements `Ctor` interface. */
    auto isEqual(const Ctor& other) const { return node::isEqual(this, other); }

    /** Implements `Node` interface. */
    auto properties() const { return node::Properties{{"value", _value}}; }

private:
    double _value;
};

} // namespace hilti::ctor
