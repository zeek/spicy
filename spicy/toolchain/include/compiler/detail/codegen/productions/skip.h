// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <utility>

#include <hilti/ast/attribute.h>

#include <spicy/compiler/detail/codegen/production.h>

namespace spicy::detail::codegen::production {

/** A production simply skipping input data. */
class Skip : public ProductionBase, public spicy::trait::isTerminal {
public:
    Skip(const std::string& symbol, const NodeRef& field, std::optional<Production> ctor,
         const Location& l = location::None)
        : ProductionBase(symbol, l), _field(field), _ctor(std::move(ctor)) {}

    const auto& field() const { return _field.as<type::unit::item::Field>(); }
    const auto& ctor() const { return _ctor; }

    auto fieldRef() const { return NodeRef(_field); }

    spicy::Type type() const { return type::void_; }
    bool nullable() const { return false; }
    bool eodOk() const {
        const auto attrs = field().attributes();
        return attrs && attrs->has("&eod");
    }
    bool atomic() const { return true; }

    std::string render() const { return hilti::util::fmt("skip: %s", _ctor ? to_string(*_ctor) : to_string(_field)); }

private:
    Node _field; // stores a shallow copy of the reference passed into ctor
    std::optional<Production> _ctor;
};

} // namespace spicy::detail::codegen::production
