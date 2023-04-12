// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <spicy/ast/types/unit.h>
#include <spicy/compiler/detail/codegen/production.h>

namespace spicy::detail::codegen::production {

namespace look_ahead {
enum class Default { First, Second, None };
} // namespace look_ahead

/**
 * A pair of alternatives between which we can decide with one token of
 * look-ahead.
 */
class LookAhead : public ProductionBase, public spicy::trait::isNonTerminal {
public:
    LookAhead(const std::string& symbol, Production alt1, Production alt2, look_ahead::Default def,
              const Location& l = location::None)
        : ProductionBase(symbol, l),
          _alternatives(std::make_pair(std::move(alt1), std::move(alt2))),
          _default(def),
          _lahs(new std::pair<std::set<Production>, std::set<Production>>) {}

    LookAhead(const std::string& symbol, Production alt1, Production alt2, const Location& l = location::None)
        : LookAhead(symbol, std::move(alt1), std::move(alt2), look_ahead::Default::None, l) {}

    /** Returns the two alternatives. */
    const std::pair<Production, Production>& alternatives() const { return _alternatives; }

    /** Returns what's the default alternative. */
    look_ahead::Default default_() const { return _default; }

    /**
     * Returns the look-aheads for the two alternatives. This function will
     * return a valid value only after the instance has been added to a
     * `Grammar`, as that's when the look-aheads are computed.
     */
    const std::pair<std::set<Production>, std::set<Production>>& lookAheads() const { return *_lahs; }

    /**
     * Sets the look-aheads for the two alternatives. This function is called
     * from a `Grammar` when the production is added to it.
     */
    void setLookAheads(std::pair<std::set<Production>, std::set<Production>>&& lahs) { *_lahs = std::move(lahs); }

    // Production API
    std::vector<std::vector<Production>> rhss() const { return {{_alternatives.first}, {_alternatives.second}}; }
    std::optional<spicy::Type> type() const { return {}; }
    bool nullable() const { return production::nullable(rhss()); }
    bool eodOk() const { return nullable(); }
    bool atomic() const { return false; }
    std::string render() const;

private:
    std::pair<Production, Production> _alternatives;
    look_ahead::Default _default;

    // This violates value-semantics but we need to share updates with
    // existing copies of the production
    std::shared_ptr<std::pair<std::set<Production>, std::set<Production>>> _lahs;
};

} // namespace spicy::detail::codegen::production
