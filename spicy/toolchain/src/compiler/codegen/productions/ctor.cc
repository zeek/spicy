// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/ctors/integer.h>
#include <hilti/ast/expressions/ctor.h>

#include <spicy/ast/builder/builder.h>
#include <spicy/compiler/detail/codegen/productions/ctor.h>

using namespace spicy;
using namespace spicy::detail;
using namespace spicy::detail::codegen;

namespace {

struct SizeVisitor final : spicy::visitor::PreOrder {
    SizeVisitor(ASTContext* context, const AttributeSet* attributes) : context(context), attributes(attributes) {}

    ASTContext* context;
    const AttributeSet* attributes;

    Expression* result = nullptr;

    auto integer(uint64_t i) const {
        return hilti::expression::Ctor::create(context, hilti::ctor::UnsignedInteger::create(context, i, 64));
    }

    void operator()(hilti::ctor::Bitfield* n) final { result = integer(n->btype()->width() / 8U); }

    void operator()(hilti::ctor::Bytes* n) final { result = integer(static_cast<uint64_t>(n->value().size())); }

    void operator()(hilti::ctor::Coerced* n) final { dispatch(n->coercedCtor()); }
    void operator()(hilti::ctor::SignedInteger* n) final { result = integer(n->width() / 8U); }
    void operator()(hilti::ctor::UnsignedInteger* n) final { result = integer(n->width() / 8U); }
};

} // namespace

Expression* production::Ctor::_bytesConsumed(ASTContext* context) const {
    const hilti::AttributeSet* attributes = nullptr;

    if ( auto* field = meta().field() )
        attributes = field->attributes();

    if ( auto* size = hilti::visitor::dispatch(SizeVisitor(context, attributes), ctor(),
                                               [](const auto& v) { return v.result; }) )
        return size;

    return nullptr;
}
