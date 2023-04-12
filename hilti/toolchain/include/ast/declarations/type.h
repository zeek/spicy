// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <utility>

#include <hilti/ast/attribute.h>
#include <hilti/ast/id.h>
#include <hilti/ast/type.h>

namespace hilti::declaration {

/** AST node for a type declaration. */
class Type : public DeclarationBase {
public:
    Type(ID id, ::hilti::Type type, Linkage linkage = Linkage::Private, Meta m = Meta())
        : DeclarationBase({std::move(id), std::move(type), node::none}, std::move(m)), _linkage(linkage) {}

    Type(ID id, ::hilti::Type type, std::optional<AttributeSet> attrs, Linkage linkage = Linkage::Private,
         Meta m = Meta())
        : DeclarationBase(nodes(std::move(id), std::move(type), std::move(attrs)), std::move(m)), _linkage(linkage) {}

    const auto& type() const { return child<hilti::Type>(1); }
    NodeRef typeRef() const { return NodeRef(children()[1]); }
    auto attributes() const { return children()[2].tryAs<AttributeSet>(); }

    bool isOnHeap() const {
        if ( auto x = attributes() )
            return x->find("&on-heap").has_value();
        else
            return false;
    }

    /** Shortcut to `type::typeID()` for the declared type. */
    auto typeID() const { return children()[1].as<hilti::Type>().typeID(); }

    /** Shortcut to `type::cxxID()` for the declared type. */
    auto cxxID() const { return children()[1].as<hilti::Type>().cxxID(); }

    /** Shortcut to `type::resolvedID()` for the declared type. */
    auto resolvedID() const { return children()[1].as<hilti::Type>().resolvedID(); }

    void setType(const ::hilti::Type& t) { children()[1] = t; }

    bool operator==(const Type& other) const { return id() == other.id() && type() == other.type(); }

    /** Internal method for use by builder API only. */
    // auto& _typeNode() { return children()[1]; }

    /** Implements `Declaration` interface. */
    bool isConstant() const { return true; }
    /** Implements `Declaration` interface. */
    const ID& id() const { return child<ID>(0); }
    /** Implements `Declaration` interface. */
    Linkage linkage() const { return _linkage; }
    /** Implements `Declaration` interface. */
    std::string displayName() const { return "type"; };
    /** Implements `Declaration` interface. */
    auto isEqual(const Declaration& other) const { return node::isEqual(this, other); }

    /** Implements `Node` interface. */
    auto properties() const { return node::Properties{{"linkage", to_string(_linkage)}}; }

private:
    Linkage _linkage;
};

} // namespace hilti::declaration
