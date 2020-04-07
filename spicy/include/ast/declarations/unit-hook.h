// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/declaration.h>
#include <hilti/ast/types/reference.h>
#include <hilti/ast/types/struct.h>
#include <spicy/ast/types/unit-items/unit-hook.h>

namespace spicy {
namespace declaration {

/** AST node for a declaration of an external (i.e., module-level) unit hook. */
class UnitHook : public hilti::NodeBase, public hilti::trait::isDeclaration {
public:
    UnitHook(ID id, Type unit, const type::unit::Item& hook, Meta m = Meta())
        : NodeBase(hilti::nodes(std::move(id), std::move(unit), hook), std::move(m)) {
        if ( ! hook.isA<type::unit::item::UnitHook>() )
            hilti::logger().internalError("non-unit hook passed into declaration::UnitHook");
    }

    std::optional<type::Unit> unitType() const {
        Type t = type::effectiveType(childs()[1].as<Type>());

        if ( auto x = t.tryAs<hilti::type::ValueReference>() )
            t = x->dereferencedType();

        if ( t.isA<type::Unit>() )
            return t.as<type::Unit>();

        if ( t.isA<type::Struct>() )
            return t.originalNode()->as<type::Unit>();

        // Not resolved yet.
        return {};
    }

    auto unitHook() const { return child<type::unit::item::UnitHook>(2); }

    bool operator==(const UnitHook& other) const {
        return unitType() == other.unitType() && unitHook() == other.unitHook();
    }

    /** Implements `Declaration` interface. */
    bool isConstant() const { return true; }
    /** Implements `Declaration` interface. */
    auto id() const { return child<ID>(0); }
    /** Implements `Declaration` interface. */
    Linkage linkage() const { return Linkage::Private; }
    /** Implements `Declaration` interface. */
    std::string displayName() const { return "unit hook"; };
    /** Implements `Declaration` interface. */
    auto isEqual(const Declaration& other) const { return node::isEqual(this, other); }

    /** Implements `Node` interface. */
    auto properties() const { return node::Properties{}; }
};

} // namespace declaration
} // namespace spicy
