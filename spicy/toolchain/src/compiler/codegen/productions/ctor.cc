// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <spicy/ast/builder/builder.h>
#include <spicy/compiler/detail/codegen/productions/ctor.h>

using namespace spicy;
using namespace spicy::detail;
using namespace spicy::detail::codegen;

struct SizeVisitor : spicy::visitor::PreOrder {
    SizeVisitor(Builder* builder, const AttributeSet* attributes) : builder(builder), attributes(attributes) {}

    Builder* builder;
    const AttributeSet* attributes;

    Expression* result = nullptr;

    void operator()(hilti::ctor::Bitfield* n) final { result = builder->integer(n->btype()->width() / 8U); }

    void operator()(hilti::ctor::Bytes* n) final {
        result = builder->integer(static_cast<uint64_t>(n->value().size()));
    }

    void operator()(hilti::ctor::Coerced* n) final { dispatch(n->coercedCtor()); }
    void operator()(hilti::ctor::SignedInteger* n) final { result = builder->integer(n->width() / 8U); }
    void operator()(hilti::ctor::UnsignedInteger* n) final { result = builder->integer(n->width() / 8U); }
};

Expression* production::Ctor::parseSize(Builder* builder) const {
    if ( ! meta().field() )
        return nullptr;

    if ( auto size = hilti::visitor::dispatch(SizeVisitor(builder, meta().field()->attributes()), _ctor,
                                              [](const auto& v) { return v.result; }) )
        return size;

    return nullptr;
}
