// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#include "spicy/ast/types/unit-items/field.h"

#include <hilti/ast/builder/all.h>
#include <hilti/ast/types/computed.h>
#include <hilti/ast/types/reference.h>
#include <hilti/ast/types/vector.h>

#include <spicy/ast/detail/visitor.h>
#include <spicy/ast/types/bitfield.h>

using namespace spicy;
using namespace spicy::detail;

namespace {

struct Visitor : public hilti::visitor::PreOrder<Type, Visitor> {
    explicit Visitor(bool want_parse_type) : want_parse_type(want_parse_type) {}

    bool want_parse_type;

    result_t operator()(const type::Bitfield& t) { return want_parse_type ? t : t.type(); }
    result_t operator()(const hilti::type::RegExp& /* t */) { return hilti::type::Bytes(); }
};

} // namespace

static Type _adaptType(Type t, bool want_parse_type) {
    if ( auto e = Visitor(want_parse_type).dispatch(t) )
        return std::move(*e);

    return t;
}

static Type _itemType(Type type, bool want_parse_type, bool is_container, Meta meta) {
    type = _adaptType(std::move(type), want_parse_type);

    if ( is_container )
        return type::Vector(std::move(type), meta);
    else
        return type;
}

Type spicy::type::unit::item::Field::parseType() const {
    return _itemType(originalType(), true, isContainer(), meta());
}

Type spicy::type::unit::item::Field::itemType() const {
    if ( auto convert = convertExpression() ) {
        return type::Computed(convert->first, [](Node& n) -> Type {
            auto& e = n.as<Expression>();

            // If there's list comprehension, morph the type into a vector.
            // Assignment will transparently work.
            if ( e.isA<hilti::expression::ListComprehension>() )
                return e.as<hilti::expression::ListComprehension>().vectorType();

            return e.type();
        });
    }

    if ( const auto& i = item(); i && i->isA<unit::item::Field>() )
        return _itemType(i->itemType(), false, isContainer(), meta());
    else
        return _itemType(originalType(), false, isContainer(), meta());
}

Type spicy::type::unit::item::Field::vectorElementTypeThroughSelf(ID id) {
    return hilti::type::Computed(hilti::builder::id("self"), [id](Node& n) {
        Type t = n.as<Expression>().type();

        if ( auto x = t.tryAs<hilti::type::ValueReference>() )
            t = x->dereferencedType();

        if ( auto x = t.tryAs<hilti::type::Struct>() )
            return x->field(id)->auxType()->as<type::Vector>().elementType();

        return hilti::type::unknown;
    });
}

std::optional<std::pair<Expression, bool>> spicy::type::unit::item::Field::convertExpression() const {
    if ( auto convert = AttributeSet::find(attributes(), "&convert") )
        return std::make_pair(*convert->valueAs<Expression>(), true);

    // The original unit type may have been replaced with the generated struct
    // already, to which the unit builder will have copied to attribute.

    auto t = parseType();

    if ( auto x = t.tryAs<type::ValueReference>() )
        t = x->dereferencedType();

    if ( auto x = t.tryAs<type::Unit>() ) {
        if ( auto convert = AttributeSet::find(x->attributes(), "&convert") )
            return std::make_pair(*convert->valueAs<Expression>(), false);
    }

    if ( auto x = t.tryAs<type::Struct>(); x && x->originalNode() ) {
        if ( auto y = x->originalNode()->tryAs<type::Unit>() ) {
            if ( auto convert = AttributeSet::find(y->attributes(), "&convert") )
                return std::make_pair(*convert->valueAs<Expression>(), false);
        }
    }

    return {};
}
