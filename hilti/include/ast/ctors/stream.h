// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/ctor.h>
#include <hilti/ast/types/stream.h>

namespace hilti {
namespace ctor {

/** AST node for a stream constructor. */
class Stream : public NodeBase, public hilti::trait::isCtor {
public:
    Stream(std::string v, Meta m = Meta()) : NodeBase(std::move(m)), _value(std::move(v)) {}

    auto value() const { return _value; }

    bool operator==(const Stream& other) const { return value() == other.value(); }

    /** Implements `Ctor` interface. */
    auto type() const { return type::Stream(); }
    /** Implements `Ctor` interface. */
    bool isConstant() const { return false; }
    /** Implements `Ctor` interface. */
    auto isLhs() const { return false; }
    /** Implements `Ctor` interface. */
    auto isTemporary() const { return true; }
    /** Implements `Ctor` interface. */
    auto isEqual(const Ctor& other) const { return node::isEqual(this, other); }

    /** Implements `Node` interface. */
    auto properties() const { return node::Properties{{"value", _value}}; }

private:
    std::string _value;
};

} // namespace ctor
} // namespace hilti
