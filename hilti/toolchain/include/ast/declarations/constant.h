// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <utility>

#include <hilti/ast/declaration.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/id.h>
#include <hilti/ast/types/unknown.h>

namespace hilti {
namespace declaration {

/** AST node for a declaration of a constant. */
class Constant : public NodeBase, public hilti::trait::isDeclaration {
public:
    Constant(ID id, ::hilti::Type type, hilti::Expression value = {}, Linkage linkage = Linkage::Private,
             Meta m = Meta())
        : NodeBase(nodes(std::move(id), std::move(type), std::move(value)), std::move(m)), _linkage(linkage) {}

    Constant(ID id, hilti::Expression value, Linkage linkage = Linkage::Private, Meta m = Meta())
        : NodeBase({std::move(id), node::none, std::move(value)}, std::move(m)), _linkage(linkage) {}

    const auto& value() const { return child<hilti::Expression>(2); }

    ::hilti::Type type() const {
        if ( auto t = childs()[1].tryAs<::hilti::Type>(); t && *t != type::unknown )
            return type::effectiveType(std::move(*t));

        return value().type();
    }

    /**
     * Returns true if the type is not explicitly specified.
     */
    auto hasAutomaticType() const { return ! childs()[1].isA<::hilti::Type>(); }

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

    /**
     * Returns a new global variable declaration with the init expression replaced.
     *
     * @param d original declaration
     * @param b new init expresssion
     * @return new declaration that's equal to original one but with the init expression replaced
     */
    static Declaration setValue(const Constant& d, const hilti::Expression& i) {
        auto x = Declaration(d)._clone().as<Constant>();
        x.childs()[2] = i;
        return std::move(x);
    }

private:
    Linkage _linkage;
};

} // namespace declaration
} // namespace hilti
