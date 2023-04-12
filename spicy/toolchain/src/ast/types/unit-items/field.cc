// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <optional>

#include <hilti/ast/builder/all.h>
#include <hilti/ast/types/reference.h>
#include <hilti/ast/types/vector.h>

#include <spicy/ast/detail/visitor.h>
#include <spicy/ast/types/bitfield.h>
#include <spicy/ast/types/unit-items/field.h>

using namespace spicy;
using namespace spicy::detail;

std::optional<std::pair<const Expression, std::optional<const Type>>> spicy::type::unit::item::Field::
    convertExpression() const {
    if ( auto convert = AttributeSet::find(attributes(), "&convert") )
        return std::make_pair((*convert->valueAsExpression()).get(), std::nullopt);

    Type t = parseType();

    if ( auto x = t.tryAs<type::ValueReference>() )
        t = x->dereferencedType();

    if ( auto x = t.tryAs<type::Unit>() ) {
        if ( auto convert = AttributeSet::find(x->attributes(), "&convert") )
            return std::make_pair(*convert->valueAsExpression(), std::move(t));
    }

    return {};
}
