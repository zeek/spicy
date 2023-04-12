// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/rt/types/time.h>

#include <hilti/ast/ctor.h>
#include <hilti/ast/types/time.h>

namespace hilti::ctor {

/** AST node for a time constructor. */
class Time : public NodeBase, public hilti::trait::isCtor {
public:
    using Value = hilti::rt::Time;

    Time(Value time, const Meta& m = Meta()) : NodeBase(nodes(type::Time(m)), m), _time(time) {}

    const auto& value() const { return _time; }

    bool operator==(const Time& other) const { return value() == other.value(); }

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
    auto properties() const { return node::Properties{{"time", to_string(_time)}}; }

private:
    Value _time;
};

} // namespace hilti::ctor
