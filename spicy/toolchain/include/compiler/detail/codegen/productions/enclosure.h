// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <utility>
#include <vector>

#include <spicy/ast/types/unit.h>
#include <spicy/compiler/detail/codegen/production.h>

namespace spicy::detail::codegen::production {

/**
 * A wrapper that forwards directly to another grammar (within the same unit
 * type). This can be used to hook into starting/finishing parsing for that
 * other grammar.
 */
class Enclosure : public ProductionBase, public spicy::trait::isNonTerminal {
public:
    Enclosure(const std::string& symbol, Production child, const Location& l = location::None)
        : ProductionBase(symbol, l), _child(std::move(child)) {}

    const Production& child() const { return _child; }

    // Production API
    std::vector<std::vector<Production>> rhss() const { return {{_child}}; };
    std::optional<spicy::Type> type() const { return _child.type(); }
    bool nullable() const { return production::nullable(rhss()); }
    bool eodOk() const { return nullable(); }
    bool atomic() const { return false; }
    std::string render() const { return _child.symbol(); }


    Production _child;
};

} // namespace spicy::detail::codegen::production
