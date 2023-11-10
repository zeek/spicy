// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <utility>

#include <hilti/ast/ctor.h>
#include <hilti/ast/types/string.h>

namespace hilti::ctor {

/** AST node for a string constructor. */
class String : public NodeBase, public hilti::trait::isCtor {
public:
    String(std::string v, bool is_literal = false, const Meta& m = Meta())
        : NodeBase(nodes(type::String(m)), m), _value(std::move(v)), _is_literal(is_literal) {}

    const auto& value() const& { return _value; }
    bool isLiteral() const { return _is_literal; }

    bool operator==(const String& other) const { return value() == other.value(); }

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
    auto properties() const { return node::Properties{{"value", _value}, {"is_literal", _is_literal}}; }

private:
    std::string _value;
    bool _is_literal = false;
};

} // namespace hilti::ctor
