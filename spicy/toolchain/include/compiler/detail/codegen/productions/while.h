// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <utility>
#include <vector>

#include <spicy/ast/types/unit.h>
#include <spicy/compiler/detail/codegen/production.h>
#include <spicy/compiler/detail/codegen/productions/look-ahead.h>

namespace spicy::detail::codegen::production {

/**
 * A production executing as long as either a given boolean expression evaluates
 * to true, or, if no expression is provided, as determined by look-ahead symbols.
 */
class While : public ProductionBase, public spicy::trait::isNonTerminal {
public:
    /**
     * Constructor for a while-loop using an expression as the condition for termination.
     */
    While(const std::string& symbol, Expression e, Production body, const Location& l = location::None)
        : ProductionBase(symbol, l), _body(std::move(body)), _expression(std::move(e)) {}

    /**
     * Constructor for a while-loop using look-ahead as the condition for
     * termination. When using this constructor, `preprocessLookAhead()` must
     * later be called with the grammar that the production has been inserted
     * into.
     */
    While(const std::string& symbol, Production body, const Location& l = location::None);

    /** Returns the loop expression if passed into the corresponding constructor. */
    const auto& expression() const { return _expression; }

    /** Returns the body production as passed into any of the constructors.  */
    const auto& body() const { return _body; }

    /**
     * Prepares the internal grammar representation for a look-ahead based
     * loop. Must be called (only) when the corresponding constructor was used.
     *
     * @param grammar grammar that while-production is being part of.
     */
    void preprocessLookAhead(Grammar* grammar);

    /**
     * For a look-ahead loop, returns the internally generated `LookAhead`
     * production that's being used for generating the code to terminate the
     * loop. The production's 1st alternative corresponds to the case of
     * terminating the loop, the 2nd alternative corresponds to executing the
     * loop body. This method must be called only after `preprocessLookAhead()`.
     */
    const production::LookAhead& lookAheadProduction() const {
        assert(_body_for_grammar); // set by preprocessLookAhead() return
        return _body_for_grammar->as<production::LookAhead>();
    }

    // Production API
    std::vector<std::vector<Production>> rhss() const { return {{(_body_for_grammar ? *_body_for_grammar : _body)}}; }
    std::optional<spicy::Type> type() const { return {}; }
    bool nullable() const { return production::nullable(rhss()); }
    bool eodOk() const { return nullable(); }
    bool atomic() const { return false; }
    std::string render() const;

private:
    Production _body;
    std::optional<Expression> _expression;
    std::optional<Production> _body_for_grammar;
};

} // namespace spicy::detail::codegen::production
