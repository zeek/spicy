// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <utility>

#include <hilti/ast/declarations/type.h>
#include <hilti/ast/function.h>
#include <hilti/ast/id.h>
#include <hilti/ast/statement.h>
#include <hilti/ast/types/struct.h>

namespace hilti::declaration {

/** AST node for a declaration of an function. */
class Function : public DeclarationBase {
public:
    Function(::hilti::Function function, Linkage linkage = Linkage::Private, Meta m = Meta())
        : DeclarationBase(nodes(std::move(function)), std::move(m)), _linkage(linkage) {}

    const ::hilti::Function& function() const { return child<::hilti::Function>(0); }

    /**
     * Returns the parent declaration associated with the function, if any. For
     * methods, this will the declaration of the corresponding struct type.
     */
    hilti::optional_ref<const Declaration> parent() const {
        if ( _parent )
            return _parent->as<Declaration>();
        else
            return {};
    }

    /**
     * If the parent declaration associated with the function refers to a valid
     * struct type, returns that type.
     */
    hilti::optional_ref<const type::Struct> parentStructType() const {
        if ( ! _parent )
            return {};

        return _parent->as<declaration::Type>().type().tryAs<type::Struct>();
    }

    void setFunction(const ::hilti::Function& f) { children()[0] = f; }
    void setLinkage(Linkage x) { _linkage = x; }
    void setParentRef(NodeRef p) {
        assert(p && p->isA<Declaration>());
        _parent = std::move(p);
    }

    bool operator==(const Function& other) const { return id() == other.id() && function() == other.function(); }

    /** Implements `Declaration` interface. */
    bool isConstant() const { return true; }
    /** Implements `Declaration` interface. */
    const ID& id() const { return function().id(); }
    /** Implements `Declaration` interface. */
    Linkage linkage() const { return _linkage; }
    /** Implements `Declaration` interface. */
    std::string displayName() const { return "function"; };
    /** Implements `Declaration` interface. */
    auto isEqual(const Declaration& other) const { return node::isEqual(this, other); }

    /** Implements `Node` interface. */
    auto properties() const {
        return node::Properties{{"linkage", to_string(_linkage)}, {"parent_type", _parent.renderedRid()}};
    }

private:
    Linkage _linkage;
    NodeRef _parent;
};

} // namespace hilti::declaration
