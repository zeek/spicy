// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <ranges>
#include <string>
#include <utility>
#include <vector>

#include <hilti/base/util.h>

#include <spicy/ast/types/unit.h>
#include <spicy/compiler/detail/codegen/production.h>
#include <spicy/compiler/detail/codegen/productions/visitor.h>

namespace spicy::detail::codegen::production {

/**
 * A production representing a block encapsulating a Block of other
 * sub-productions to be parsed sequentially. This is conceptually similar to a
 * sequence, but with some additional higher-level features, like support for
 * parsing attributes and an optional condition.
 */
class Block : public Production {
public:
    Block(ASTContext* /* ctx */, const std::string& symbol, std::vector<std::unique_ptr<Production>> prods,
          Expression* condition = nullptr, std::vector<std::unique_ptr<Production>> else_prods = {},
          AttributeSet* attributes = nullptr, const Location& l = location::None)
        : Production(symbol, l),
          _prods(std::move(prods)),
          _else_prods(std::move(else_prods)),
          _condition(condition),
          _attributes(attributes) {}

    const auto& productions() const { return _prods; }
    const auto& elseProductions() const { return _else_prods; }
    auto* condition() const { return _condition; }
    auto* attributes() const { return _attributes; }

    bool isAtomic() const final { return false; };
    bool isEodOk() const final { return isNullable(); };
    bool isLiteral() const final { return false; };
    bool isNullable() const final { return production::isNullable(rhss()); };
    bool isTerminal() const final { return false; };

    std::vector<std::vector<Production*>> rhss() const final {
        std::vector<std::vector<Production*>> rhss = {
            hilti::util::toVector(std::ranges::transform_view(_prods, [](const auto& p) { return p.get(); }))};

        if ( ! _else_prods.empty() )
            rhss.emplace_back(
                hilti::util::toVector(std::ranges::transform_view(_else_prods, [](const auto& p) { return p.get(); })));

        return rhss;
    }

    std::string dump() const final {
        auto true_ =
            hilti::util::join(std::ranges::transform_view(_prods, [](const auto& p) { return p->symbol(); }), " ");
        auto false_ =
            hilti::util::join(std::ranges::transform_view(_else_prods, [](const auto& p) { return p->symbol(); }), " ");

        if ( false_.empty() )
            return true_;
        else
            return hilti::util::fmt("(%s) else (%s)", true_, false_);
    }

    SPICY_PRODUCTION

private:
    std::vector<std::unique_ptr<Production>> _prods;
    std::vector<std::unique_ptr<Production>> _else_prods;
    Expression* _condition = nullptr;
    AttributeSet* _attributes = nullptr;
};

} // namespace spicy::detail::codegen::production
