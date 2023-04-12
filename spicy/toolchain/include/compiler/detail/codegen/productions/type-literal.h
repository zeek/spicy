// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <utility>

#include <hilti/ast/expressions/type.h>

#include <spicy/compiler/detail/codegen/production.h>

namespace spicy::detail::codegen::production {

/**
 * A literal represented by a type. A type can only be used as literals if
 * the parsing can for tell for sure that an instance of it must be coming
 * up. This is, e.g., the case for embedded objects.
 */
class TypeLiteral : public ProductionBase, public spicy::trait::isLiteral {
public:
    TypeLiteral(const std::string& symbol, spicy::Type type, const Location& l = location::None)
        : ProductionBase(symbol, l), _type(std::move(type)) {}

    Expression expression() const { return hilti::expression::Type_(_type); }
    std::optional<spicy::Type> type() const { return _type; }
    bool nullable() const { return false; }
    bool eodOk() const { return nullable(); }
    bool atomic() const { return true; }
    int64_t tokenID() const { return static_cast<int64_t>(production::tokenID(hilti::util::fmt("%s", _type))); }
    std::string render() const { return hilti::util::fmt("%s", _type); }

private:
    spicy::Type _type;
};

} // namespace spicy::detail::codegen::production
