// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <spicy/ast/hook.h>
#include <spicy/ast/types/unit-items/field.h>
#include <spicy/ast/types/unit.h>

using namespace spicy;

hilti::optional_ref<const spicy::type::Unit> Hook::unitType() const {
    if ( _unit_type )
        return _unit_type->as<spicy::type::Unit>();
    else
        return {};
}

hilti::optional_ref<const spicy::type::unit::item::Field> Hook::unitField() const {
    if ( _unit_field )
        return _unit_field->as<spicy::type::unit::item::Field>();
    else
        return {};
}

std::optional<Expression> Hook::priority() const {
    if ( auto p = AttributeSet::find(function().attributes(), "priority") )
        return *p->valueAsExpression();

    return {};
}

NodeRef Hook::ddRef() const {
    if ( children()[1].isA<Declaration>() )
        return NodeRef(children()[1]);
    else
        return {};
}
