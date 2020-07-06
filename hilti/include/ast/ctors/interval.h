// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/rt/types/interval.h>

#include <hilti/ast/ctor.h>
#include <hilti/ast/types/interval.h>

namespace hilti {
namespace ctor {

/** AST node for a interval constructor. */
class Interval : public NodeBase, public hilti::trait::isCtor {
public:
    using Value = hilti::rt::Interval;

    Interval(const Value& interval, Meta m = Meta()) : NodeBase(std::move(m)), _interval(interval) {}

    const auto& value() const { return _interval; }

    bool operator==(const Interval& other) const { return value() == other.value(); }

    /** Implements `Ctor` interface. */
    auto type() const { return type::Interval(meta()); }
    /** Implements `Ctor` interface. */
    bool isConstant() const { return true; }
    /** Implements `Ctor` interface. */
    auto isLhs() const { return false; }
    /** Implements `Ctor` interface. */
    auto isTemporary() const { return true; }
    /** Implements `Ctor` interface. */
    auto isEqual(const Ctor& other) const { return node::isEqual(this, other); }
    /** Implements `Node` interface. */
    auto properties() const { return node::Properties{{"interval", to_string(_interval)}}; }

private:
    Value _interval;
};

} // namespace ctor
} // namespace hilti
