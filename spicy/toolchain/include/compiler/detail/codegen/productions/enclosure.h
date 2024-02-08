// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
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
class Enclosure : public Production {
public:
    Enclosure(ASTContext* /* ctx */, const std::string& symbol, std::unique_ptr<Production> child,
              const Location& l = location::None)
        : Production(symbol, l), _child(std::move(child)) {}

    const auto* child() const { return _child.get(); }

    bool isAtomic() const final { return false; };
    bool isEodOk() const final { return isNullable(); };
    bool isLiteral() const final { return false; };
    bool isNullable() const final { return production::isNullable(rhss()); };
    bool isTerminal() const final { return false; };

    std::vector<std::vector<Production*>> rhss() const final { return {{_child.get()}}; };
    QualifiedTypePtr type() const final { return _child->type(); };

    std::string dump() const override { return _child->symbol(); }

    SPICY_PRODUCTION

private:
    std::unique_ptr<Production> _child;
};

} // namespace spicy::detail::codegen::production
