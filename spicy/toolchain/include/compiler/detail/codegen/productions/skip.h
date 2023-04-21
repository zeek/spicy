// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <utility>

#include <hilti/ast/attribute.h>

#include <spicy/ast/types/unit-items/skip.h>
#include <spicy/compiler/detail/codegen/production.h>

namespace spicy::detail::codegen::production {

/** A production simply skipping input data. */
class Skip : public ProductionBase, public spicy::trait::isTerminal {
public:
    Skip(const std::string& symbol, const NodeRef& skip, const Location& l = location::None)
        : ProductionBase(symbol, l), _skip(skip) {}

    const auto& skip() const { return _skip.as<type::unit::item::Skip>(); }
    auto skipRef() const { return NodeRef(_skip); }

    spicy::Type type() const { return type::void_; }
    bool nullable() const { return false; }
    bool eodOk() const { return skip().attributes().has("&eod"); }
    bool atomic() const { return true; }
    std::string render() const { return "skip"; }

private:
    Node _skip; // stores a shallow copy of the reference passed into ctor
};

} // namespace spicy::detail::codegen::production
