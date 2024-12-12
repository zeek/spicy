// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <spicy/ast/types/unit.h>
#include <spicy/compiler/detail/codegen/production.h>
#include <spicy/compiler/detail/codegen/productions/look-ahead.h>
#include <spicy/compiler/detail/codegen/productions/visitor.h>

namespace spicy::detail::codegen::production {

/**
 * A production executing as long as either a given boolean expression evaluates
 * to true, or, if no expression is provided, as determined by look-ahead symbols.
 */
class While : public Production {
public:
    /**
     * Constructor for a while-loop using an expression as the condition for termination.
     */
    While(ASTContext* /* ctx */, const std::string& symbol, Expression* e, std::unique_ptr<Production> body,
          const Location& l = location::None)
        : Production(symbol, l), _body(std::move(body)), _expression(e) {}

    /**
     * Constructor for a while-loop using look-ahead as the condition for
     * termination. When using this constructor, `preprocessLookAhead()` must
     * later be called with the grammar that the production has been inserted
     * into.
     */
    While(const std::string& symbol, std::unique_ptr<Production> body, const Location& l = location::None);

    /** Returns the body production as passed into any of the constructors.  */
    const auto& body() const { return _body; }

    /**
     * Prepares the internal grammar representation for a look-ahead based
     * loop. Must be called (only) when the corresponding constructor was used.
     *
     * @param ctx context to use for generating AST nodes.
     * @param grammar grammar that while-production is being part of.
     */
    void preprocessLookAhead(ASTContext* ctx, Grammar* grammar);

    /**
     * For a look-ahead loop, returns the internally generated `LookAhead`
     * production that's being used for generating the code to terminate the
     * loop. The production's 1st alternative corresponds to the case of
     * terminating the loop, the 2nd alternative corresponds to executing the
     * loop body. This method must be called only after `preprocessLookAhead()`.
     */
    const production::LookAhead* lookAheadProduction() const {
        assert(_body_for_grammar); // set by preprocessLookAhead() return
        return _body_for_grammar->as<production::LookAhead>();
    }

    bool isAtomic() const final { return false; }
    bool isEodOk() const final { return isNullable(); }
    bool isLiteral() const final { return false; }
    bool isNullable() const final { return production::isNullable(rhss()); }
    bool isTerminal() const final { return false; }

    std::vector<std::vector<Production*>> rhss() const final {
        return {{(_body_for_grammar ? _body_for_grammar.get() : _body.get())}};
    }

    /** Returns the loop expression if passed into the corresponding constructor. */
    Expression* expression() const final { return _expression; }

    Expression* _bytesConsumed(ASTContext* context) const final { return nullptr; }

    std::string dump() const final;

    SPICY_PRODUCTION

private:
    std::unique_ptr<Production> _body;
    Expression* _expression = nullptr;
    std::unique_ptr<Production> _body_for_grammar;
};

} // namespace spicy::detail::codegen::production
