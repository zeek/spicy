// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/builder/all.h>
#include <hilti/ast/types/computed.h>
#include <spicy/ast/detail/visitor.h>
#include <spicy/ast/types/bitfield.h>
#include <spicy/ast/types/unit-items/field.h>

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

Type spicy::type::unit::item::Field::parseType() const { return _adaptType(*this, _originalType(), false); }

Type spicy::type::unit::item::Field::itemType() const {
    if ( isContainer() ) {
        auto itype = _adaptType(*this, parseType().as<type::Vector>().elementType(), true);
        return type::Vector(itype, itype.meta());
    }

    if ( auto a = AttributeSet::find(attributes(), "&convert") )
        return hilti::type::Computed(*a->valueAs<Expression>(), meta());

    return _adaptType(*this, _originalType(), true);
}
