// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/rt/types/network.h>

#include <hilti/ast/ctor.h>
#include <hilti/ast/types/network.h>

namespace hilti {
namespace ctor {

/** AST node for a Network constructor. */
class Network : public NodeBase, public hilti::trait::isCtor {
public:
    using Value = hilti::rt::Network;

    Network(const Value& network, Meta m = Meta()) : NodeBase(std::move(m)), _network(network) {}

    const auto& value() const { return _network; }

    bool operator==(const Network& other) const { return value() == other.value(); }

    /** Implements `Ctor` interface. */
    auto type() const { return type::Network(meta()); }
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

} // namespace ctor
} // namespace hilti
