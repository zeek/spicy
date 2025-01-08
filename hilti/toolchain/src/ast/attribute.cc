// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

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
        return result::Error(hilti::util::fmt("attribute '%s' requires an expression", to_string(kind())));

    if ( ! value()->isA<Expression>() )
        return result::Error(hilti::util::fmt("value for attribute '%s' must be an expression", to_string(kind())));

    return {value()->as<Expression>()};
}

Result<std::string> Attribute::valueAsString() const {
    if ( ! hasValue() )
        return result::Error(hilti::util::fmt("attribute '%s' requires a string", to_string(kind())));

    if ( auto e = value()->tryAs<expression::Ctor>() )
        if ( auto s = e->ctor()->tryAs<ctor::String>() )
            return s->value();

    return result::Error(hilti::util::fmt("value for attribute '%s' must be a string", to_string(kind())));
}

Result<int64_t> Attribute::valueAsInteger() const {
    if ( ! hasValue() )
        return result::Error(hilti::util::fmt("attribute '%s' requires an integer", to_string(kind())));

    if ( auto e = value()->tryAs<expression::Ctor>() ) {
        if ( auto s = e->ctor()->tryAs<ctor::SignedInteger>() )
            return s->value();

        if ( auto s = e->ctor()->tryAs<ctor::UnsignedInteger>() )
            return static_cast<int64_t>(s->value());
    }

    return result::Error(hilti::util::fmt("value for attribute '%s' must be an integer", to_string(kind())));
}

Result<bool> Attribute::coerceValueTo(Builder* builder, QualifiedType* dst) {
    if ( ! dst->isResolved() )
        return result::Error("cannot coerce attribute value to unresolved type");

    if ( auto e = valueAsExpression() ) {
        auto ne = coerceExpression(builder, *e, dst);
        if ( ! ne.coerced )
            return result::Error(hilti::util::fmt("cannot coerce attribute's expression from type '%s' to '%s' (%s)",
                                                  *(*e)->type(), *dst, to_string(kind())));

        if ( ! ne.nexpr )
            return false;

        setChild(builder->context(), 0, ne.nexpr);
        return true;
    }
    else
        return result::Error("cannot coerce non-expression attribute value");
}

std::string Attribute::_dump() const { return ""; }

std::string AttributeSet::_dump() const { return ""; }

Attribute* AttributeSet::find(attribute::Kind kind) const {
    for ( const auto& a : attributes() )
        if ( a->kind() == kind )
            return a;

    return {};
}

hilti::node::Set<Attribute> AttributeSet::findAll(attribute::Kind kind) const {
    hilti::node::Set<Attribute> result;

    for ( const auto& a : attributes() )
        if ( a->kind() == kind )
            result.push_back(a);

    return result;
}

void AttributeSet::remove(attribute::Kind kind) {
    while ( const auto& a = find(kind) )
        removeChild(a);
}
