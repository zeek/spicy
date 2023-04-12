// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <utility>

#include <hilti/ast/expressions/ctor.h>

#include <spicy/compiler/detail/codegen/production.h>

namespace spicy::detail::codegen::production {

/** A literal represented by a ctor. */
class Ctor : public ProductionBase, public spicy::trait::isLiteral {
public:
    Ctor(const std::string& symbol, spicy::Ctor ctor, const Location& l = location::None)
        : ProductionBase(symbol, l), _ctor(std::move(ctor)) {}

    spicy::Ctor ctor() const { return _ctor; };
    Expression expression() const { return hilti::expression::Ctor(_ctor); }
    std::optional<spicy::Type> type() const { return _ctor.type(); }
    bool nullable() const { return false; }
    bool eodOk() const { return nullable(); }
    bool atomic() const { return true; }

    int64_t tokenID() const {
        return static_cast<int64_t>(production::tokenID(hilti::util::fmt("%s|%s", _ctor, _ctor.type())));
    }

    std::string render() const { return hilti::util::fmt("%s (%s)", _ctor, _ctor.type()); }

    spicy::Ctor _ctor;
};

} // namespace spicy::detail::codegen::production
