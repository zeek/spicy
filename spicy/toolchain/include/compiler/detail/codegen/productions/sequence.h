// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <algorithm>
#include <string>
#include <utility>
#include <vector>

#include <hilti/base/util.h>

#include <spicy/ast/types/unit.h>
#include <spicy/compiler/detail/codegen/production.h>

namespace spicy::detail::codegen::production {

/**
 * A wrapper that forwards directly to another grammar (within the same unit
 * type). This can be used to hook into starting/finishing parsing for that
 * other grammar.
 */
class Sequence : public ProductionBase, public spicy::trait::isNonTerminal {
public:
    Sequence(const std::string& symbol, std::vector<Production> prods, const Location& l = location::None)
        : ProductionBase(symbol, l), _prods(std::move(prods)) {}

    const std::vector<Production>& sequence() const { return _prods; }
    void add(Production p) { _prods.push_back(std::move(p)); }

    // Production API
    std::vector<std::vector<Production>> rhss() const { return {_prods}; };
    std::optional<spicy::Type> type() const { return {}; }
    bool nullable() const { return production::nullable(rhss()); }
    bool eodOk() const { return nullable(); }
    bool atomic() const { return false; }
    std::string render() const {
        return hilti::util::join(hilti::util::transform(_prods, [](const auto& p) { return p.symbol(); }), " ");
    }


    std::vector<Production> _prods;
};

} // namespace spicy::detail::codegen::production
