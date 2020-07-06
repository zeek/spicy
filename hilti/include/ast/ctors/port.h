// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/rt/types/port.h>

#include <hilti/ast/ctor.h>
#include <hilti/ast/types/port.h>

namespace hilti {
namespace ctor {

/** AST node for a port constructor. */
class Port : public NodeBase, public hilti::trait::isCtor {
public:
    using Value = hilti::rt::Port;

    Port(const Value& port, Meta m = Meta()) : NodeBase(std::move(m)), _port(port) {}

    const auto& value() const { return _port; }

    bool operator==(const Port& other) const { return value() == other.value(); }

    /** Implements `Ctor` interface. */
    auto type() const { return type::Port(meta()); }
    /** Implements `Ctor` interface. */
    bool isConstant() const { return true; }
    /** Implements `Ctor` interface. */
    auto isLhs() const { return false; }
    /** Implements `Ctor` interface. */
    auto isTemporary() const { return true; }
    /** Implements `Ctor` interface. */
    auto isEqual(const Ctor& other) const { return node::isEqual(this, other); }
    /** Implements `Node` interface. */
    auto properties() const { return node::Properties{{"port", to_string(_port)}}; }

private:
    Value _port;
};

} // namespace ctor
} // namespace hilti
