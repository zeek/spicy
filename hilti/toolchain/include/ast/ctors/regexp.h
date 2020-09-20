// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <utility>
#include <vector>

#include <hilti/ast/attribute.h>
#include <hilti/ast/ctor.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/types/regexp.h>

namespace hilti {
namespace ctor {

/** AST node for a RegExp constructor. */
class RegExp : public NodeBase, public hilti::trait::isCtor {
public:
    RegExp(std::vector<std::string> p, std::optional<AttributeSet> attrs = {}, Meta m = Meta())
        : NodeBase(nodes(std::move(attrs)), std::move(m)), _patterns(std::move(p)) {}

    auto attributes() const { return childs()[0].tryAs<AttributeSet>(); }
    const auto& value() const { return _patterns; }

    auto isNoSub() const { return AttributeSet::find(attributes(), "&nosub"); }

    bool operator==(const RegExp& other) const { return value() == other.value(); }

    /** Implements `Ctor` interface. */
    auto type() const { return type::RegExp(meta()); }
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

} // namespace ctor
} // namespace hilti
