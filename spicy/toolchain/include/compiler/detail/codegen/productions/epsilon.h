// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <utility>

#include <spicy/ast/builder/builder.h>
#include <spicy/compiler/detail/codegen/production.h>
#include <spicy/compiler/detail/codegen/productions/visitor.h>

namespace spicy::detail::codegen::production {

/** Empty epsilon production. */
class Epsilon : public Production {
public:
    Epsilon(ASTContext* /* ctx */, Location l = location::None) : Production("<epsilon>", std::move(l)) {}

    bool isAtomic() const final { return true; };
    bool isEodOk() const final { return isNullable(); };
    bool isLiteral() const final { return false; };
    bool isNullable() const final { return true; };
    bool isTerminal() const final { return true; };

    Expression* _bytesConsumed(ASTContext* context) const final {
        return hilti::expression::Ctor::create(context, hilti::ctor::UnsignedInteger::create(context, 0, 64));
    }

    std::string dump() const final { return "()"; }

    SPICY_PRODUCTION
};

} // namespace spicy::detail::codegen::production
