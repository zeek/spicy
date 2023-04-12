// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <utility>
#include <vector>

#include <spicy/ast/types/unit.h>
#include <spicy/compiler/detail/codegen/production.h>

namespace spicy::detail::codegen::production {

/** A production executing until interrupted by a foreach hook. */
class ForEach : public ProductionBase, public spicy::trait::isNonTerminal {
public:
    ForEach(const std::string& symbol, Production body, bool eod_ok, const Location& l = location::None)
        : ProductionBase(symbol, l), _body(std::move(body)), _eod_ok(eod_ok) {}

    const Production& body() const { return _body; }

    // Production API
    std::vector<std::vector<Production>> rhss() const { return {{_body}}; }
    std::optional<spicy::Type> type() const { return {}; }
    bool nullable() const { return production::nullable(rhss()); }
    bool eodOk() const { return _eod_ok ? _eod_ok : nullable(); }
    bool atomic() const { return false; }
    std::string render() const { return hilti::util::fmt("foreach: %s", _body.symbol()); }

private:
    Production _body;
    bool _eod_ok;
};

} // namespace spicy::detail::codegen::production
