// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <utility>
#include <vector>

#include <hilti/ast/declaration.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/id.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/auto.h>

namespace hilti::declaration {

/** AST node for a declaration of global variable. */
class GlobalVariable : public DeclarationBase {
public:
    GlobalVariable(ID id, ::hilti::Type type, std::optional<hilti::Expression> init = {},
                   Linkage linkage = Linkage::Private, Meta m = Meta())
        : DeclarationBase(nodes(std::move(id), std::move(type), std::move(init)), std::move(m)), _linkage(linkage) {}

    GlobalVariable(ID id, ::hilti::Type type, Linkage linkage = Linkage::Private, Meta m = Meta())
        : DeclarationBase(nodes(std::move(id), std::move(type), node::none), std::move(m)), _linkage(linkage) {}

    GlobalVariable(ID id, hilti::Expression init, Linkage linkage = Linkage::Private, Meta m = Meta())
        : DeclarationBase(nodes(std::move(id), node::none, std::move(init)), std::move(m)), _linkage(linkage) {}

    GlobalVariable(ID id, ::hilti::Type type, std::vector<hilti::Expression> args,
                   std::optional<hilti::Expression> init = {}, Linkage linkage = Linkage::Private, Meta m = Meta())
        : DeclarationBase(nodes(std::move(id), std::move(type), std::move(init), std::move(args)), std::move(m)),
          _linkage(linkage) {}

    auto init() const { return children()[2].tryAs<hilti::Expression>(); }

    const auto& type() const {
        if ( auto t = children()[1].tryAs<hilti::Type>() )
            return *t;
        else {
            assert(init());
            return init()->type();
        }
    }

    auto typeArguments() const { return children<hilti::Expression>(3, -1); }

    void setInit(const hilti::Expression& i) { children()[2] = i; }
    void setTypeArguments(std::vector<hilti::Expression> args) {
        auto& c = children();
        c.erase(c.begin() + 3, c.end());
        for ( auto&& a : args )
            c.emplace_back(std::move(a));
    }

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

private:
    Linkage _linkage;
};

} // namespace hilti::declaration
