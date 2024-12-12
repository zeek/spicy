// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/ctors/integer.h>
#include <hilti/ast/expressions/ctor.h>
#include <hilti/ast/expressions/unresolved-operator.h>

#include <spicy/ast/builder/builder.h>
#include <spicy/compiler/detail/codegen/productions/variable.h>

using namespace spicy;
using namespace spicy::detail;
using namespace spicy::detail::codegen;

namespace {

struct SizeVisitor final : spicy::visitor::PreOrder {
    SizeVisitor(ASTContext* context, const AttributeSet* attributes) : context(context), attributes(attributes) {}

    ASTContext* context;
    const AttributeSet* attributes = nullptr;
    Expression* result = nullptr;

    auto integer(uint64_t i) const {
        return hilti::expression::Ctor::create(context, hilti::ctor::UnsignedInteger::create(context, i, 64));
    }

    void operator()(hilti::type::Address* n) final {
        if ( attributes && attributes->has(attribute::kind::IPv4) )
            result = integer(4U);
        else if ( attributes && attributes->has(attribute::kind::IPv6) )
            result = integer(16U);
        else
            hilti::rt::cannot_be_reached();
    }

    void operator()(hilti::type::Bitfield* n) final { result = integer(n->width() / 8U); }

    void operator()(hilti::type::Real*) final {
        hilti::Attribute* attr_type = nullptr;

        if ( attributes )
            attr_type = attributes->find(attribute::kind::Type);

        if ( ! attr_type )
            hilti::logger().internalError("real value must have a &type attribute");

        result = hilti::expression::Ternary::
            create(context,
                   hilti::expression::UnresolvedOperator::
                       create(context, hilti::operator_::Kind::Equal,
                              {*attr_type->valueAsExpression(),
                               hilti::expression::Name::create(context, "spicy::RealType::IEEE754_Single")}),
                   integer(4U), integer(8U));
    }

    void operator()(hilti::type::SignedInteger* n) final { result = integer(n->width() / 8U); }
    void operator()(hilti::type::UnsignedInteger* n) final { result = integer(n->width() / 8U); }
    void operator()(hilti::type::Void* n) final { result = integer(0U); }
};

} // namespace

Expression* production::Variable::_bytesConsumed(ASTContext* context) const {
    hilti::AttributeSet* attributes = nullptr;

    if ( auto* field = meta().field() )
        attributes = field->attributes();

    if ( auto* size = hilti::visitor::dispatch(SizeVisitor(context, attributes), _type->type(),
                                               [](const auto& v) { return v.result; }) )
        return size;

    return nullptr;
}
