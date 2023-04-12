// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <utility>

#include <spicy/compiler/detail/codegen/production.h>

namespace spicy::detail::codegen::production {

/** Empty epsilon production. */
class Epsilon : public ProductionBase, spicy::trait::isTerminal {
public:
    Epsilon(Location l = location::None) : ProductionBase("<epsilon>", std::move(l)) {}

    bool nullable() const { return true; }
    bool eodOk() const { return nullable(); }
    bool atomic() const { return true; }
    std::optional<spicy::Type> type() const { return {}; }
    std::string render() const { return "()"; }
};

} // namespace spicy::detail::codegen::production
