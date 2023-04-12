// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <algorithm>
#include <string>
#include <utility>
#include <vector>

#include <spicy/ast/types/unit.h>
#include <spicy/compiler/detail/codegen/production.h>

namespace spicy::detail::codegen {
class Grammar;
} // namespace spicy::detail::codegen

namespace spicy::detail::codegen::production {

/**
 * A type described by another grammar from an independent `type::Unit` type.
 */
class Unit : public ProductionBase, public spicy::trait::isNonTerminal {
public:
    Unit(const std::string& symbol, type::Unit type, std::vector<Expression> args, std::vector<Production> fields,
         const Location& l = location::None)
        : ProductionBase(symbol, l), _type(std::move(type)), _args(std::move(args)), _fields(std::move(fields)) {}

    const type::Unit& unitType() const { return _type; }
    const auto& arguments() const { return _args; }
    const auto& fields() const { return _fields; }

    // Production API
    std::vector<std::vector<Production>> rhss() const { return {_fields}; };
    std::optional<spicy::Type> type() const { return spicy::Type(_type); }
    bool nullable() const { return production::nullable(rhss()); }
    bool eodOk() const { return nullable(); }
    bool atomic() const { return false; }
    std::string render() const {
        return hilti::util::join(hilti::util::transform(_fields, [](const auto& p) { return p.symbol(); }), " ");
    }

private:
    type::Unit _type;
    std::vector<Expression> _args;
    std::vector<Production> _fields;
};

} // namespace spicy::detail::codegen::production
