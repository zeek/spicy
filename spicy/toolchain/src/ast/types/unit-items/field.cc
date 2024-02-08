// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/types/name.h>
#include <hilti/ast/types/reference.h>
#include <hilti/ast/visitor.h>

#include <spicy/ast/builder/builder.h>
#include <spicy/ast/types/unit-items/field.h>
#include <spicy/ast/types/unit.h>

using namespace spicy;
using namespace spicy::detail;

std::optional<std::pair<ExpressionPtr, QualifiedTypePtr>> type::unit::item::Field::convertExpression() const {
    if ( auto convert = attributes()->find("&convert") )
        return std::make_pair(*convert->valueAsExpression(), nullptr);

    auto t = parseType();

    if ( auto x = t->type()->tryAs<hilti::type::ValueReference>() )
        t = x->dereferencedType();

    if ( auto x = t->type()->tryAs<type::Unit>() ) {
        if ( auto convert = x->attributes()->find("&convert") )
            return std::make_pair(*convert->valueAsExpression(), std::move(t));
    }

    return {};
}

void type::unit::item::Field::setDDType(ASTContext* ctx, const QualifiedTypePtr& t) {
    setChild(ctx, 0, hilti::expression::Keyword::createDollarDollarDeclaration(ctx, t));
}

struct SizeVisitor : hilti::visitor::PreOrder {
    SizeVisitor(Builder* builder, const spicy::type::unit::item::Field& field) : builder(builder), field(field) {}

    Builder* builder;
    const spicy::type::unit::item::Field& field;
    ExpressionPtr result;

    void operator()(hilti::type::Address* n) final {
        if ( field.attributes()->has("&ipv4") )
            result = builder->integer(4U);
        else if ( field.attributes()->has("&ipv6") )
            result = builder->integer(16U);
        else
            hilti::rt::cannot_be_reached();
    }

    void operator()(hilti::type::SignedInteger* n) final { result = builder->integer(n->width() / 8U); }
    void operator()(hilti::type::UnsignedInteger* n) final { result = builder->integer(n->width() / 8U); }
    void operator()(hilti::type::Bitfield* n) final { result = builder->integer(n->width() / 8U); }

    void operator()(hilti::type::Real*) final {
        auto type = *field.attributes()->find("&type")->valueAsExpression();
        result = builder->ternary(builder->equal(type, builder->id("spicy::RealType::IEEE754_Single")),
                                  builder->integer(4U), builder->integer(8U));
    }
};

ExpressionPtr spicy::type::unit::item::Field::size(ASTContext* ctx) const {
    Builder builder(ctx);

    if ( const auto& size = attributes()->find("&size") )
        return *size->valueAsExpression();

    if ( auto size = hilti::visitor::dispatch(SizeVisitor(&builder, *this), parseType()->type(),
                                              [](const auto& v) { return v.result; }) )
        return size;

    return nullptr;
}
