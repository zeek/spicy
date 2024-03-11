// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>
#include <utility>

#include <hilti/ast/expressions/type.h>

#include <spicy/compiler/detail/codegen/production.h>
#include <spicy/compiler/detail/codegen/productions/visitor.h>

namespace spicy::detail::codegen::production {

/**
 * A literal represented by a type. A type can only be used as literals if
 * the parsing can for tell for sure that an instance of it must be coming
 * up. This is, e.g., the case for embedded objects.
 */
class TypeLiteral : public Production {
public:
    TypeLiteral(ASTContext* ctx, const std::string& symbol, QualifiedType* type, const Location& l = location::None)
        : Production(symbol, l), _type(type), _expr(hilti::expression::Type_::create(ctx, _type)) {}

    bool isAtomic() const final { return true; };
    bool isEodOk() const final { return false; };
    bool isLiteral() const final { return true; };
    bool isNullable() const final { return false; };
    bool isTerminal() const final { return true; };

    Expression* expression() const final { return _expr; }
    QualifiedType* type() const final { return _type; };
    int64_t tokenID() const final { return static_cast<int64_t>(Production::tokenID(_type->print())); }

    std::string dump() const final { return _type->print(); }

    SPICY_PRODUCTION

private:
    QualifiedType* _type = nullptr;
    Expression* _expr = nullptr;
};

} // namespace spicy::detail::codegen::production
