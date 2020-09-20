// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <utility>
#include <vector>

#include <hilti/ast/declaration.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/id.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/unknown.h>

namespace hilti {
namespace declaration {

/** AST node for a declaration of global variable. */
class GlobalVariable : public NodeBase, public hilti::trait::isDeclaration {
public:
    GlobalVariable(ID id, ::hilti::Type type, Linkage linkage = Linkage::Private, Meta m = Meta())
        : NodeBase(nodes(std::move(id), std::move(type), node::none), std::move(m)), _linkage(linkage) {}

    GlobalVariable(ID id, ::hilti::Type type, std::optional<hilti::Expression> init = {},
                   Linkage linkage = Linkage::Private, Meta m = Meta())
        : NodeBase(nodes(std::move(id), std::move(type), std::move(init)), std::move(m)), _linkage(linkage) {}

    GlobalVariable(ID id, ::hilti::Type type, std::vector<hilti::Expression> args,
                   std::optional<hilti::Expression> init = {}, Linkage linkage = Linkage::Private, Meta m = Meta())
        : NodeBase(nodes(std::move(id), std::move(type), std::move(init), std::move(args)), std::move(m)),
          _linkage(linkage) {}

    GlobalVariable(ID id, hilti::Expression init, Linkage linkage = Linkage::Private, Meta m = Meta())
        : NodeBase(nodes(std::move(id), node::none, std::move(init)), std::move(m)), _linkage(linkage) {}

    auto init() const { return childs()[2].tryAs<hilti::Expression>(); }
    auto typeArguments() const { return childs<hilti::Expression>(3, -1); }

    ::hilti::Type type() const {
        if ( auto t = childs()[1].tryAs<::hilti::Type>(); t && *t != type::unknown )
            return type::effectiveType(std::move(*t));

        if ( auto i = init() )
            return i->type();

        return type::unknown;
    }

    /**
     * Returns true if this is an `auto` variable, i.e., the type is derived
     * from the initialization expression.
     */
    auto hasAutomaticType() const { return ! childs()[1].isA<::hilti::Type>(); }

    bool operator==(const GlobalVariable& other) const {
        return id() == other.id() && type() == other.type() && init() == other.init();
    }

    /** Implements `Declaration` interface. */
    bool isConstant() const { return false; }
    /** Implements `Declaration` interface. */
    const ID& id() const { return child<ID>(0); }
    /** Implements `Declaration` interface. */
    Linkage linkage() const { return _linkage; }
    /** Implements `Declaration` interface. */
    std::string displayName() const { return "global variable"; };
    /** Implements `Declaration` interface. */
    auto isEqual(const Declaration& other) const { return node::isEqual(this, other); }

    /** Implements `Node` interface. */
    auto properties() const { return node::Properties{{"linkage", to_string(_linkage)}}; }

    /**
     * Returns a new global variable declaration with its type replaced.
     *
     * @param d original declaration
     * @param b new type
     * @return new declaration that's equal to original one but with the type replaced
     */
    static Declaration setType(const GlobalVariable& d, std::optional<hilti::Type> t) {
        auto x = Declaration(d)._clone().as<GlobalVariable>();
        if ( t )
            x.childs()[1] = *t;
        else
            x.childs()[1] = node::none;

        return std::move(x);
    }

    /**
     * Returns a new global variable declaration with the init expression replaced.
     *
     * @param d original declaration
     * @param b new init expresssion
     * @return new declaration that's equal to original one but with the init expression replaced
     */
    static Declaration setInit(const GlobalVariable& d, const hilti::Expression& i) {
        auto x = Declaration(d)._clone().as<GlobalVariable>();
        x.childs()[2] = i;
        return std::move(x);
    }

    /**
     * Returns a new global variable declaration with the type argument expressions replaced.
     *
     * @param d original declaration
     * @param i new init expresssion
     * @return new declaration that's equal to original one but with the init expression replaced
     */
    static Declaration setTypeArguments(const GlobalVariable& d, std::vector<hilti::Expression> args) {
        auto x = Declaration(d)._clone().as<GlobalVariable>();
        x.childs() = x.childs<Node>(0, 3);
        for ( auto&& a : args )
            x.childs().emplace_back(std::move(a));

        return std::move(x);
    }

private:
    Linkage _linkage;
};

} // namespace declaration
} // namespace hilti
