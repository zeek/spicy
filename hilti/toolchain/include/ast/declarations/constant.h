// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <utility>

#include <hilti/ast/declaration.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/id.h>
#include <hilti/ast/types/auto.h>

namespace hilti::declaration {

/** AST node for a declaration of a constant. */
class Constant : public DeclarationBase {
public:
    Constant(ID id, ::hilti::Type type, hilti::Expression value = {}, Linkage linkage = Linkage::Private,
             Meta m = Meta())
        : DeclarationBase(nodes(std::move(id), std::move(type), std::move(value)), std::move(m)), _linkage(linkage) {}

    Constant(ID id, hilti::Expression value, Linkage linkage = Linkage::Private, Meta m = Meta())
        : DeclarationBase(nodes(std::move(id), node::none, std::move(value)), std::move(m)), _linkage(linkage) {}

    const auto& value() const { return child<hilti::Expression>(2); }

    const auto& type() const {
        if ( auto t = children()[1].tryAs<hilti::Type>() )
            return *t;
        else
            return value().type();
    }

    void setValue(const hilti::Expression& i) { children()[2] = i; }

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

} // namespace hilti::declaration
