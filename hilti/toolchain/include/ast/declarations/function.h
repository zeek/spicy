// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <utility>

#include <hilti/ast/function.h>
#include <hilti/ast/id.h>
#include <hilti/ast/statement.h>

namespace hilti {
namespace declaration {

/** AST node for a declaration of an function. */
class Function : public NodeBase, public hilti::trait::isDeclaration {
public:
    Function(::hilti::Function function, Linkage linkage = Linkage::Private, Meta m = Meta())
        : NodeBase({std::move(function)}, std::move(m)), _linkage(linkage) {}

    const auto& function() const { return child<::hilti::Function>(0); }

    bool operator==(const Function& other) const { return id() == other.id() && function() == other.function(); }

    /** Implements `Declaration` interface. */
    bool isConstant() const { return true; }
    /** Implements `Declaration` interface. */
    ID id() const { return function().id(); }
    /** Implements `Declaration` interface. */
    Linkage linkage() const { return _linkage; }
    /** Implements `Declaration` interface. */
    std::string displayName() const { return "function"; };
    /** Implements `Declaration` interface. */
    auto isEqual(const Declaration& other) const { return node::isEqual(this, other); }

    /** Implements `Node` interface. */
    auto properties() const { return node::Properties{{"linkage", to_string(_linkage)}}; }

    /**
     * Returns a new function declaration with the body replaced.
     *
     * @param d original declaration
     * @param b new body
     * @return new declaration that's equal to original one but with the body replaced
     */
    static Declaration setBody(const Function& d, const Statement& b) {
        auto x = Declaration(d)._clone().as<Function>();
        x.childs()[0] = hilti::Function::setBody(x.childs()[0].as<::hilti::Function>(), b);
        return x;
    }

private:
    Linkage _linkage;
};

} // namespace declaration
} // namespace hilti
