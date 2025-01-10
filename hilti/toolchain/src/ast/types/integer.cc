// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <algorithm>
#include <exception>

#include <hilti/ast/ctors/integer.h>
#include <hilti/ast/types/integer.h>

using namespace hilti;
using namespace hilti::type;

SignedInteger* type::SignedInteger::create(ASTContext* ctx, unsigned int width, const Meta& m) {
    return ctx->make<SignedInteger>(ctx, {}, width, m);
}

UnsignedInteger* type::UnsignedInteger::create(ASTContext* ctx, unsigned int width, const Meta& m) {
    return ctx->make<UnsignedInteger>(ctx, {}, width, m);
}
