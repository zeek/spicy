// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#include "spicy/ast/types/unit-items/field.h"

#include <hilti/ast/builder/all.h>
#include <hilti/ast/types/computed.h>
#include <hilti/ast/types/vector.h>

#include <spicy/ast/detail/visitor.h>
#include <spicy/ast/types/bitfield.h>

using namespace spicy;
using namespace spicy::detail;

namespace {

struct Visitor : public hilti::visitor::PreOrder<Type, Visitor> {
    explicit Visitor(const type::unit::item::Field& field, bool want_item_type)
        : field(field), want_item_type(want_item_type) {}

    const type::unit::item::Field& field;
    bool want_item_type;

    result_t operator()(const type::Bitfield& t) { return want_item_type ? t.type() : t; }

    result_t operator()(const hilti::type::RegExp& /* t */) { return hilti::type::Bytes(); }
};

} // namespace

static Type _adaptType(const type::unit::item::Field& field, const Type& t, bool want_item_type) {
    if ( auto e = Visitor(field, want_item_type).dispatch(t) )
        return std::move(*e);

    return type::effectiveType(t);
}

Type spicy::type::unit::item::Field::parseType() const {
    auto orig_type = originalType();

    if ( isContainer() ) {
        Type etype = orig_type.as<type::Vector>().elementType();
        auto itype = _adaptType(*this, etype, false);
        return type::Vector(itype, itype.meta());
    }

    return _adaptType(*this, std::move(orig_type), false);
}

Type spicy::type::unit::item::Field::itemType() const {
    if ( auto a = AttributeSet::find(attributes(), "&convert") ) {
        hilti::type::Computed::Callback cb = [](Node& n) -> Type {
            auto t = type::effectiveType(n.as<Expression>().type());

            // If there's list comprehension, morph the type into a vector.
            // Assignment will transparently work.
            if ( auto x = t.tryAs<type::List>() )
                return hilti::type::Vector(x->elementType(), x->meta());

            return t;
        };

        return hilti::type::Computed(*a->valueAs<Expression>(), cb, meta());
    }

    if ( isContainer() ) {
        Type etype = originalType().as<type::Vector>().elementType();
        auto itype = _adaptType(*this, etype, true);
        return type::Vector(itype, itype.meta());
    }

    return _adaptType(*this, originalType(), true);
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
