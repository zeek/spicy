// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <algorithm>
#include <exception>

#include <hilti/ast/ctors/integer.h>
#include <hilti/ast/types/integer.h>

using namespace hilti;
using namespace hilti::type;

std::shared_ptr<SignedInteger> type::SignedInteger::create(ASTContext* ctx, unsigned int width, const Meta& m) {
    return std::shared_ptr<SignedInteger>(new SignedInteger(ctx, {}, width, m));
}

std::shared_ptr<UnsignedInteger> type::UnsignedInteger::create(ASTContext* ctx, unsigned int width, const Meta& m) {
    return std::shared_ptr<UnsignedInteger>(new UnsignedInteger(ctx, {}, width, m));
}
