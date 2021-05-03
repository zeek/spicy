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
        // Helper to adapt the type of a &convert expression further.
        const auto adapt_type = [](const Type& t) -> Type {
            if ( t.isA<type::Unknown>() )
                return t;

            // If there's list comprehension, morph the type into a vector.
            // Assignment will transparently work.
            if ( auto x = t.tryAs<type::List>() )
                return hilti::type::Vector(x->elementType(), x->meta());

            return t;
        };

        if ( convert->second ) {
            // For a unit-level &convert, we derive the type of the expression
            // from the __convert() function that the code generator creates to
            // evaluate it. That function has an "auto" return type that will
            // eventually be resolved to the correct type. (Note there's no
            // __convert function for field-level attribute.)
            //
            // This approach is bit messy, but ensures that "self" inside the
            // expression gets resolved correctly independent of where the
            // itemType() that this method returns will be used. (Which
            // otherwise could be a problem because of our current way of
            // dynamically computing types. This will become more
            // straight-forward once we clean up type resolving.)
            auto& unit = convert->second->as<type::Unit>();
            auto t = hilti::builder::typeByID(ID(*unit.typeID()));
            return type::Computed(t, [adapt_type](Node& n) -> Type {
                auto t = n.as<Type>();

                if ( auto x = t.tryAs<hilti::type::ValueReference>() )
                    t = x->dereferencedType();

                auto st = t.tryAs<hilti::type::Struct>();
                if ( ! st )
                    return type::unknown;

                auto field = st->field("__convert");
                assert(field);

                auto f = field->type().as<type::Function>();
                return adapt_type(f.result().type());
            });
        }
        else {
            return type::Computed(convert->first, [&adapt_type](Node& n) -> Type {
                auto t = type::effectiveType(n.as<Expression>().type());
                return adapt_type(t);
            });
        }
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

std::optional<std::pair<Expression, std::optional<Type>>> spicy::type::unit::item::Field::convertExpression() const {
    if ( auto convert = AttributeSet::find(attributes(), "&convert") )
        return std::make_pair(*convert->valueAs<Expression>(), std::nullopt);

    auto t = parseType();

    if ( auto x = t.tryAs<type::ValueReference>() )
        t = x->dereferencedType();

    if ( auto x = t.tryAs<type::Unit>() ) {
        if ( auto convert = AttributeSet::find(x->attributes(), "&convert") )
            return std::make_pair(*convert->valueAs<Expression>(), x);
    }

    // The original unit type may have been replaced with the generated struct
    // already.
    if ( auto x = t.tryAs<type::Struct>(); x && x->originalNode() ) {
        if ( auto y = x->originalNode()->tryAs<type::Unit>() ) {
            if ( auto convert = AttributeSet::find(y->attributes(), "&convert") )
                return std::make_pair(*convert->valueAs<Expression>(), y);
        }
    }

    return {};
}
