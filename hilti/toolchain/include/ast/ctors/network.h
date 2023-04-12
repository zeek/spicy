// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/rt/types/network.h>

#include <hilti/ast/ctor.h>
#include <hilti/ast/types/network.h>

namespace hilti::ctor {

/** AST node for a Network constructor. */
class Network : public NodeBase, public hilti::trait::isCtor {
public:
    using Value = hilti::rt::Network;

    Network(const Value& network, const Meta& m = Meta()) : NodeBase(nodes(type::Network(m)), m), _network(network) {}

    const auto& value() const { return _network; }

    bool operator==(const Network& other) const { return value() == other.value(); }

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
    auto properties() const { return node::Properties{{"network", to_string(_network)}}; }

private:
    Value _network;
};

} // namespace hilti::ctor
