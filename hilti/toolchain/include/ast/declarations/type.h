// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <utility>

#include <hilti/ast/attribute.h>
#include <hilti/ast/id.h>
#include <hilti/ast/type.h>

namespace hilti {
namespace declaration {

/** AST node for a type declaration. */
class Type : public NodeBase, public hilti::trait::isDeclaration {
public:
    Type(ID id, ::hilti::Type type, Linkage linkage = Linkage::Private, Meta m = Meta())
        : NodeBase({std::move(id), std::move(type), node::none}, std::move(m)), _linkage(linkage) {}

    Type(ID id, ::hilti::Type type, std::optional<AttributeSet> attrs, Linkage linkage = Linkage::Private,
         Meta m = Meta())
        : NodeBase(nodes(std::move(id), std::move(type), std::move(attrs)), std::move(m)), _linkage(linkage) {}

    auto type() const { return type::effectiveType(child<hilti::Type>(1)); }
    auto attributes() const { return childs()[2].tryReferenceAs<AttributeSet>(); }

    bool isOnHeap() const {
        if ( type::isOnHeap(type()) )
            return true;

        auto x = attributes();
        return x && x->find("&on-heap");
    }

    /** Shortcut to `type::typeID()` for the declared type. */
    auto typeID() const { return childs()[1].as<hilti::Type>().typeID(); }

    /** Shortcut to `type::cxxID()` for the declared type. */
    auto cxxID() const { return childs()[1].as<hilti::Type>().cxxID(); }

    bool operator==(const Type& other) const { return id() == other.id() && type() == other.type(); }

    /** Internal method for use by builder API only. */
    auto& _typeNode() { return childs()[1]; }

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

    /**
     * Returns a new type declaration with the resolving type replaced.
     *
     * @param d original declaration
     * @param t new type
     * @return new declaration that's equal to original one but with the resolving type replaced
     */
    static Type setType(const Type& d, const ::hilti::Type& t) {
        auto x = Declaration(d)._clone().as<Type>();
        x.childs()[1] = t;
        return x;
    }

private:
    Linkage _linkage;
};

} // namespace declaration
} // namespace hilti
