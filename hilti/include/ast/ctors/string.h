// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/ctor.h>
#include <hilti/ast/types/string.h>

namespace hilti {
namespace ctor {

/** AST node for a string constructor. */
class String : public NodeBase, public hilti::trait::isCtor {
public:
    String(std::string v, Meta m = Meta()) : NodeBase(std::move(m)), _value(std::move(v)) {}

    auto value() const { return _value; }

    bool operator==(const String& other) const { return value() == other.value(); }

    /** Implements `Ctor` interface. */
    auto type() const { return type::String(); }
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
    std::string _value;
};

} // namespace ctor
} // namespace hilti
