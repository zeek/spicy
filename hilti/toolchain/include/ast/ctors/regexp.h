// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <utility>
#include <vector>

#include <hilti/ast/attribute.h>
#include <hilti/ast/ctor.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/types/regexp.h>

namespace hilti::ctor {

/** AST node for a RegExp constructor. */
class RegExp : public NodeBase, public hilti::trait::isCtor {
public:
    RegExp(std::vector<std::string> p, std::optional<AttributeSet> attrs = {}, Meta m = Meta())
        : NodeBase(nodes(type::RegExp(m), std::move(attrs)), std::move(m)), _patterns(std::move(p)) {}

    auto attributes() const { return children()[1].tryAs<AttributeSet>(); }
    const auto& value() const { return _patterns; }

    /**
     * Returns true if this pattern does not need support for capturing groups.
     */
    bool isNoSub() const { return AttributeSet::find(attributes(), "&nosub").has_value(); }

    bool operator==(const RegExp& other) const { return value() == other.value(); }

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
    auto properties() const { return node::Properties{{"patterns", util::join(_patterns, " | ")}}; }

private:
    std::vector<std::string> _patterns;
};

} // namespace hilti::ctor
