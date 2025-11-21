// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <algorithm>
#include <memory>
#include <ranges>
#include <string>
#include <utility>
#include <vector>

#include <spicy/ast/types/unit.h>
#include <spicy/compiler/detail/codegen/production.h>
#include <spicy/compiler/detail/codegen/productions/visitor.h>

#include "base/util.h"

namespace spicy::detail::codegen {
class Grammar;
} // namespace spicy::detail::codegen

namespace spicy::detail::codegen::production {

/**
 * A type described by another grammar from an independent `type::Unit` type.
 */
class Unit : public Production {
public:
    Unit(ASTContext* ctx, const std::string& symbol, type::Unit* type, Expressions args,
         std::vector<std::unique_ptr<Production>> fields, const Location& l = location::None)
        : Production(symbol, l),
          _type(QualifiedType::create(ctx, type, hilti::Constness::Const)),
          _args(std::move(args)),
          _fields(std::move(fields)) {}

    auto unitType() const { return _type->type()->as<type::Unit>(); }
    const auto& arguments() const { return _args; }
    const auto& fields() const { return _fields; }

    bool isAtomic() const final { return false; };
    bool isEodOk() const final { return isNullable(); };
    bool isLiteral() const final { return false; };
    bool isNullable() const final { return production::isNullable(rhss()); };
    bool isTerminal() const final { return false; };

    std::vector<std::vector<Production*>> rhss() const final {
        return {hilti::util::toVector(_fields | std::views::transform([](const auto& p) { return p.get(); }))};
    }

    QualifiedType* type() const final { return _type; };

    std::string dump() const final {
        return hilti::util::join(_fields | std::views::transform([](const auto& p) { return p->symbol(); }), " ");
    }

    SPICY_PRODUCTION

private:
    QualifiedType* _type = nullptr;
    Expressions _args;
    std::vector<std::unique_ptr<Production>> _fields;
};

} // namespace spicy::detail::codegen::production
