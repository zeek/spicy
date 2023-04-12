// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <utility>

#include <hilti/ast/declaration.h>
#include <hilti/ast/types/reference.h>
#include <hilti/ast/types/struct.h>

#include <spicy/ast/hook.h>

namespace spicy::declaration {

/** AST node for a declaration of an external (i.e., module-level) unit hook. */
class UnitHook : public hilti::DeclarationBase {
public:
    UnitHook(const ID& id, const Hook& hook, Meta m = Meta()) : DeclarationBase(hilti::nodes(id, hook), std::move(m)) {
        children()[1].as<Hook>().setID(id);
    }

    const auto& hook() const { return child<Hook>(1); }

    bool operator==(const UnitHook& other) const { return id() == other.id() && hook() == other.hook(); }

    /** Implements `Declaration` interface. */
    bool isConstant() const { return true; }
    /** Implements `Declaration` interface. */
    const ID& id() const { return child<ID>(0); }
    /** Implements `Declaration` interface. */
    Linkage linkage() const { return Linkage::Private; }
    /** Implements `Declaration` interface. */
    std::string displayName() const { return "unit hook"; };
    /** Implements `Declaration` interface. */
    auto isEqual(const Declaration& other) const { return node::isEqual(this, other); }

    /** Implements `Node` interface. */
    auto properties() const { return node::Properties{}; }
};

} // namespace spicy::declaration
