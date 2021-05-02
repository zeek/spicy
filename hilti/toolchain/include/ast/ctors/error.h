// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <utility>

#include <hilti/ast/ctor.h>
#include <hilti/ast/types/error.h>

namespace hilti {
namespace ctor {

/** AST node for an error constructor. */
class Error : public NodeBase, public hilti::trait::isCtor {
public:
    Error(std::string v, Meta m = Meta()) : NodeBase(nodes(type::Error(m)), m), _value(std::move(v)) {}

    auto value() const { return _value; }

    bool operator==(const Error& other) const { return value() == other.value(); }

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
    std::string _value;
};

} // namespace ctor
} // namespace hilti
