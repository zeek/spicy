// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <utility>

#include <hilti/ast/attribute.h>
#include <hilti/ast/declaration.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/id.h>

namespace hilti::declaration {

/** AST node for a declaration of an expression. */
class Expression : public DeclarationBase {
public:
    Expression(ID id, hilti::Expression e, Linkage linkage = Linkage::Private, Meta m = Meta())
        : DeclarationBase(nodes(std::move(id), std::move(e), node::none), std::move(m)), _linkage(linkage) {}
    Expression(ID id, hilti::Expression e, std::optional<AttributeSet> attrs, Linkage linkage = Linkage::Private,
               Meta m = Meta())
        : DeclarationBase(nodes(std::move(id), std::move(e), std::move(attrs)), std::move(m)), _linkage(linkage) {}

    const auto& expression() const { return child<hilti::Expression>(1); }
    auto attributes() const { return children()[2].tryAs<AttributeSet>(); }

    bool operator==(const Expression& other) const { return id() == other.id() && expression() == other.expression(); }

    /** Implements `Declaration` interface. */
    bool isConstant() const { return true; }
    /** Implements `Declaration` interface. */
    const ID& id() const { return child<ID>(0); }
    /** Implements `Declaration` interface. */
    Linkage linkage() const { return _linkage; }
    /** Implements `Declaration` interface. */
    std::string displayName() const { return "expression"; };
    /** Implements `Declaration` interface. */
    auto isEqual(const Declaration& other) const { return node::isEqual(this, other); }

    /** Implements `Node` interface. */
    auto properties() const { return node::Properties{{"linkage", to_string(_linkage)}}; }

private:
    Linkage _linkage;
};

} // namespace hilti::declaration
