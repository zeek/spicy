// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <spicy/compiler/detail/codegen/production.h>
#include <spicy/compiler/detail/codegen/productions/visitor.h>

namespace spicy::detail::codegen::production {

namespace look_ahead {
enum class Default { First, Second, None };
} // namespace look_ahead

/**
 * A pair of alternatives between which we can decide with one token of
 * look-ahead.
 */
class LookAhead : public Production {
public:
    LookAhead(ASTContext* /* ctx */, const std::string& symbol, std::unique_ptr<Production> alt1,
              std::unique_ptr<Production> alt2, look_ahead::Default def, const Location& l = location::None)
        : Production(symbol, l), _alternatives(std::make_pair(std::move(alt1), std::move(alt2))), _default(def) {}

    LookAhead(ASTContext* ctx, const std::string& symbol, std::unique_ptr<Production> alt1,
              std::unique_ptr<Production> alt2, const Location& l = location::None)
        : LookAhead(ctx, symbol, std::move(alt1), std::move(alt2), look_ahead::Default::None, l) {}

    /** Returns the two alternatives. */
    std::pair<Production*, Production*> alternatives() const {
        return std::make_pair(_alternatives.first.get(), _alternatives.second.get());
    }

    /** Returns what's the default alternative. */
    const auto& default_() const { return _default; }

    bool isAtomic() const final { return false; };
    bool isEodOk() const final { return isNullable(); };
    bool isLiteral() const final { return false; };
    bool isNullable() const final { return production::isNullable(rhss()); };
    bool isTerminal() const final { return false; };

    std::vector<std::vector<Production*>> rhss() const final {
        return {{_alternatives.first.get()}, {_alternatives.second.get()}};
    }

    std::string dump() const final;

    /**
     * Returns the look-aheads for the two alternatives. This function will
     * return a valid value only after the instance has been added to a
     * `Grammar`, as that's when the look-aheads are computed.
     */
    const auto& lookAheads() const { return _lahs; }

    /**
     * Sets the look-aheads for the two alternatives. This function is called
     * from a `Grammar` when the production is added to it.
     */
    void setLookAheads(std::pair<std::set<Production*>, std::set<Production*>>&& lahs) { _lahs = std::move(lahs); }

    SPICY_PRODUCTION

private:
    std::pair<std::unique_ptr<Production>, std::unique_ptr<Production>> _alternatives;

    look_ahead::Default _default;

    std::pair<std::set<Production*>, std::set<Production*>> _lahs;
};

} // namespace spicy::detail::codegen::production
