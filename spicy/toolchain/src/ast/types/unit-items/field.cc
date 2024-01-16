// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include "ast/types/unit-items/field.h"

#include <optional>

#include <hilti/ast/builder/all.h>
#include <hilti/ast/types/bitfield.h>
#include <hilti/ast/types/reference.h>
#include <hilti/ast/types/vector.h>

#include <spicy/ast/detail/visitor.h>

using namespace hilti;
using namespace spicy;
using namespace spicy::detail;

namespace builder = hilti::builder;

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

struct SizeVisitor : visitor::PreOrder<Expression, SizeVisitor> {
    SizeVisitor(const spicy::type::unit::item::Field& field) : _field(field) {}

    const spicy::type::unit::item::Field& _field;

    result_t operator()(const spicy::type::Address&) {
        if ( AttributeSet::find(_field.attributes(), "&ipv4") )
            return builder::integer(4U);
        else if ( AttributeSet::find(_field.attributes(), "&ipv6") )
            return builder::integer(16U);
        else
            hilti::rt::cannot_be_reached();
    }

    result_t operator()(const spicy::type::SignedInteger& n) { return builder::integer(n.width() / 8U); }
    result_t operator()(const spicy::type::UnsignedInteger& n) { return builder::integer(n.width() / 8U); }
    result_t operator()(const spicy::type::Bitfield& n) { return builder::integer(n.width() / 8U); }

    result_t operator()(const spicy::type::Real&) {
        auto type = *_field.attributes()->find("&type")->valueAsExpression();
        return builder::ternary(builder::equal(type, builder::id("spicy::RealType::IEEE754_Single")),
                                builder::integer(4U), builder::integer(8U));
    }
};

std::optional<const Expression> spicy::type::unit::item::Field::size() const {
    if ( const auto& size = AttributeSet::find(attributes(), "&size") )
        return {size.value().valueAsExpression()->get()};

    if ( auto size = SizeVisitor(*this).dispatch(parseType()) )
        return {*std::move(size)};

    return {};
}
