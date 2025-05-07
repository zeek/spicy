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

    Expression* parseSize(Builder* builder) const final { return builder->integer(0U); }

    std::string dump() const final { return "()"; }

    SPICY_PRODUCTION
};

} // namespace spicy::detail::codegen::production
