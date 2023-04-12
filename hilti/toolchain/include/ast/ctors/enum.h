// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/ctor.h>
#include <hilti/ast/declarations/type.h>
#include <hilti/ast/types/enum.h>

namespace hilti::ctor {

/** AST node for an enum constructor. */
class Enum : public NodeBase, public hilti::trait::isCtor {
public:
    Enum(type::enum_::Label v, Meta m = Meta()) : NodeBase(nodes(std::move(v)), std::move(m)) {}

    const auto& value() const { return children()[0].as<type::enum_::Label>(); }

    bool operator==(const Enum& other) const { return value() == other.value(); }

    /** Implements `Ctor` interface. */
    const auto& type() const { return value().enumType(); }

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

} // namespace hilti::ctor
