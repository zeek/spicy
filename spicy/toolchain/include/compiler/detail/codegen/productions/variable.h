// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <utility>

#include <spicy/compiler/detail/codegen/production.h>

namespace spicy::detail::codegen::production {

/**
 * A variable. A variable is a terminal that will be parsed from the input
 * stream according to its type, yet is not recognizable as such in advance
 * by just looking at the available bytes. If we start parsing, we assume it
 * will match (and if not, generate a parse error).
 */
class Variable : public ProductionBase, public spicy::trait::isTerminal {
public:
    Variable(const std::string& symbol, spicy::Type type, const Location& l = location::None)
        : ProductionBase(symbol, l), _type(std::move(type)) {}

    spicy::Type type() const { return _type; }
    bool nullable() const { return false; }
    bool eodOk() const { return nullable(); }
    bool atomic() const { return true; }
    std::string render() const { return hilti::util::fmt("%s", _type); }

private:
    spicy::Type _type;
};

} // namespace spicy::detail::codegen::production
