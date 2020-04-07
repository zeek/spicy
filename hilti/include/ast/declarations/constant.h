// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/declaration.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/id.h>

namespace hilti {
namespace declaration {

/** AST node for a declaration of a constant. */
class Constant : public NodeBase, public hilti::trait::isDeclaration {
public:
    Constant(ID id, hilti::Expression value, Linkage linkage = Linkage::Private, Meta m = Meta())
        : NodeBase({std::move(id), std::move(value)}, std::move(m)), _linkage(linkage) {}

    auto value() const { return child<hilti::Expression>(1); }

    bool operator==(const Constant& other) const { return id() == other.id() && value() == other.value(); }

    /** Implements `Declaration` interface. */
    bool isConstant() const { return true; }
    /** Implements `Declaration` interface. */
    const ID& id() const { return child<ID>(0); }
    /** Implements `Declaration` interface. */
    Linkage linkage() const { return _linkage; }
    /** Implements `Declaration` interface. */
    std::string displayName() const { return "constant"; };
    /** Implements `Declaration` interface. */
    auto isEqual(const Declaration& other) const { return node::isEqual(this, other); }

    /** Implements `Node` interface. */
    auto properties() const { return node::Properties{{"linkage", to_string(_linkage)}}; }

private:
    Linkage _linkage;
};

} // namespace declaration
} // namespace hilti
