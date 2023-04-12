// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <utility>

#include <hilti/ast/declaration.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/id.h>

namespace hilti::declaration {

/** AST node for a declaration of a module property. */
class Property : public DeclarationBase {
public:
    Property(ID id, Meta m = Meta()) : DeclarationBase(nodes(std::move(id), node::none), std::move(m)) {}

    Property(ID id, hilti::Expression attr, Meta m = Meta())
        : DeclarationBase(nodes(std::move(id), std::move(attr)), std::move(m)) {}

    auto expression() const { return children()[1].tryAs<hilti::Expression>(); }

    bool operator==(const Property& other) const { return id() == other.id() && expression() == other.expression(); }

    /** Implements `Declaration` interface. */
    bool isConstant() const { return true; }
    /** Implements `Declaration` interface. */
    const ID& id() const { return child<ID>(0); }
    /** Implements `Declaration` interface. */
    Linkage linkage() const { return Linkage::Private; }
    /** Implements `Declaration` interface. */
    std::string displayName() const { return "property"; };
    /** Implements `Declaration` interface. */
    auto isEqual(const Declaration& other) const { return node::isEqual(this, other); }

    /** Implements `Node` interface. */
    auto properties() const { return node::Properties{}; }
};

} // namespace hilti::declaration
