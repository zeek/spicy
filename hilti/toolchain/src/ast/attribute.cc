// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <optional>

#include <hilti/ast/attribute.h>
#include <hilti/ast/builder/builder.h>
#include <hilti/ast/ctors/integer.h>
#include <hilti/ast/ctors/string.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/expressions/ctor.h>
#include <hilti/ast/type.h>
#include <hilti/ast/visitor.h>
#include <hilti/compiler/coercer.h>

using namespace hilti;

Result<Expression*> Attribute::valueAsExpression() const {
    if ( ! hasValue() )
        return result::Error(hilti::util::fmt("attribute '%s' requires an expression", attributeName()));

    if ( ! value()->isA<Expression>() )
        return result::Error(hilti::util::fmt("value for attribute '%s' must be an expression", attributeName()));

    return {value()->as<Expression>()};
}

Result<std::string> Attribute::valueAsString() const {
    if ( ! hasValue() )
        return result::Error(hilti::util::fmt("attribute '%s' requires a string", attributeName()));

    if ( auto e = value()->tryAs<expression::Ctor>() )
        if ( auto s = e->ctor()->tryAs<ctor::String>() )
            return s->value();

    return result::Error(hilti::util::fmt("value for attribute '%s' must be a string", attributeName()));
}

Result<int64_t> Attribute::valueAsInteger() const {
    if ( ! hasValue() )
        return result::Error(hilti::util::fmt("attribute '%s' requires an integer", attributeName()));

    if ( auto e = value()->tryAs<expression::Ctor>() ) {
        if ( auto s = e->ctor()->tryAs<ctor::SignedInteger>() )
            return s->value();

        if ( auto s = e->ctor()->tryAs<ctor::UnsignedInteger>() )
            return static_cast<int64_t>(s->value());
    }

    return result::Error(hilti::util::fmt("value for attribute '%s' must be an integer", attributeName()));
}

Result<bool> Attribute::coerceValueTo(Builder* builder, QualifiedType* dst) {
    if ( ! dst->isResolved() )
        return result::Error("cannot coerce attribute value to unresolved type");

    if ( auto e = valueAsExpression() ) {
        auto ne = coerceExpression(builder, *e, dst);
        if ( ! ne.coerced )
            return result::Error(hilti::util::fmt("cannot coerce attribute's expression from type '%s' to '%s' (%s)",
                                                  *(*e)->type(), *dst, attributeName()));

        if ( ! ne.nexpr )
            return false;

        setChild(builder->context(), 0, ne.nexpr);
        return true;
    }
    else
        return result::Error("cannot coerce non-expression attribute value");
}

std::optional<Attribute::Kind> Attribute::tagToKind(std::string_view tag) {
    if ( auto found = _attr_map.find(tag); found != _attr_map.end() )
        return found->second;

    return {};
}

std::string_view Attribute::kindToString(Kind kind) {
    for ( auto&& [name, tag] : _attr_map ) {
        if ( tag == kind )
            return name;
    }

    util::cannotBeReached();
}

std::string Attribute::_dump() const { return ""; }

std::string AttributeSet::_dump() const { return ""; }

Attribute* AttributeSet::find(Attribute::Kind kind) const {
    for ( const auto& a : attributes() )
        if ( a->kind() == kind )
            return a;

    return {};
}

hilti::node::Set<Attribute> AttributeSet::findAll(Attribute::Kind kind) const {
    hilti::node::Set<Attribute> result;

    for ( const auto& a : attributes() )
        if ( a->kind() == kind )
            result.push_back(a);

    return result;
}

void AttributeSet::remove(Attribute::Kind kind) {
    while ( const auto& a = find(kind) )
        removeChild(a);
}
