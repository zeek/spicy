// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <hilti/ast/types/name.h>
#include <hilti/ast/types/reference.h>
#include <hilti/ast/visitor.h>
#include <hilti/base/logger.h>

#include <spicy/ast/builder/builder.h>
#include <spicy/ast/types/unit-items/field.h>
#include <spicy/ast/types/unit.h>

using namespace spicy;
using namespace spicy::detail;

std::optional<std::pair<Expression*, QualifiedType*>> type::unit::item::Field::convertExpression() const {
    if ( auto* convert = attributes()->find(attribute::kind::Convert) )
        return std::make_pair(*convert->valueAsExpression(), nullptr);

    auto* t = parseType();

    if ( auto* x = t->type()->tryAs<hilti::type::ValueReference>() )
        t = x->dereferencedType();

    if ( auto* x = t->type()->tryAs<type::Unit>() ) {
        if ( auto* convert = x->attributes()->find(attribute::kind::Convert) )
            return std::make_pair(*convert->valueAsExpression(), t);
    }

    return {};
}

void type::unit::item::Field::setDDType(ASTContext* ctx, QualifiedType* t) {
    setChild(ctx, 0, hilti::expression::Keyword::createDollarDollarDeclaration(ctx, t));
}
