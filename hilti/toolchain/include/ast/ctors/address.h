// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/rt/types/address.h>

#include <hilti/ast/ctor.h>
#include <hilti/ast/types/address.h>

namespace hilti::ctor {

/** AST node for a Address constructor. */
class Address : public NodeBase, public hilti::trait::isCtor {
public:
    using Value = hilti::rt::Address;

    Address(const Value& addr, const Meta& m = Meta()) : NodeBase(nodes(type::Address(m)), m), _address(addr) {}

    const auto& value() const { return _address; }

    bool operator==(const Address& other) const { return value() == other.value(); }

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
    auto properties() const { return node::Properties{{"address", to_string(_address)}}; }

private:
    Value _address;
};

} // namespace hilti::ctor
