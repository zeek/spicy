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

Result<ExpressionPtr> Attribute::valueAsExpression() const {
    if ( ! hasValue() )
        return result::Error(hilti::util::fmt("attribute '%s' requires an expression", _tag));

    if ( ! value()->isA<Expression>() )
        return result::Error(hilti::util::fmt("value for attribute '%s' must be an expression", _tag));

    return {value()->as<Expression>()};
}

Result<std::string> Attribute::valueAsString() const {
    if ( ! hasValue() )
        return result::Error(hilti::util::fmt("attribute '%s' requires a string", _tag));

    if ( auto e = value()->tryAs<expression::Ctor>() )
        if ( auto s = e->ctor()->tryAs<ctor::String>() )
            return s->value();

    return result::Error(hilti::util::fmt("value for attribute '%s' must be a string", _tag));
}

Result<int64_t> Attribute::valueAsInteger() const {
    if ( ! hasValue() )
        return result::Error(hilti::util::fmt("attribute '%s' requires an integer", _tag));

    if ( auto e = value()->tryAs<expression::Ctor>() ) {
        if ( auto s = e->ctor()->tryAs<ctor::SignedInteger>() )
            return s->value();

        if ( auto s = e->ctor()->tryAs<ctor::UnsignedInteger>() )
            return static_cast<int64_t>(s->value());
    }

    return result::Error(hilti::util::fmt("value for attribute '%s' must be an integer", _tag));
}

Result<bool> Attribute::coerceValueTo(Builder* builder, const QualifiedTypePtr& dst) {
    if ( ! dst->isResolved() )
        return result::Error("cannot coerce attribute value to unresolved type");

    if ( auto e = valueAsExpression() ) {
        auto ne = coerceExpression(builder, *e, dst);
        if ( ! ne.coerced )
            return result::Error(hilti::util::fmt("cannot coerce attribute's expression from type '%s' to '%s' (%s)",
                                                  *(*e)->type(), *dst, tag()));

        if ( ! ne.nexpr )
            return false;

        setChild(builder->context(), 0, std::move(ne.nexpr));
        return true;
    }
    else
        return result::Error("cannot coerce non-expression attribute value");
}

std::string Attribute::_dump() const { return ""; }

std::string AttributeSet::_dump() const { return ""; }

AttributePtr AttributeSet::find(std::string_view tag) const {
    for ( const auto& a : attributes() )
        if ( a->tag() == tag )
            return a;

    return {};
}

hilti::node::Set<Attribute> AttributeSet::findAll(std::string_view tag) const {
    hilti::node::Set<Attribute> result;

    for ( const auto& a : attributes() )
        if ( a->tag() == tag )
            result.push_back(a);

    return result;
}

void AttributeSet::remove(std::string_view tag) {
    while ( const auto& a = find(tag) )
        removeChild(a);
}
