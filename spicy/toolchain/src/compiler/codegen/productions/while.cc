// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <utility>

#include <spicy/compiler/detail/codegen/grammar.h>
#include <spicy/compiler/detail/codegen/production.h>
#include <spicy/compiler/detail/codegen/productions/deferred.h>
#include <spicy/compiler/detail/codegen/productions/epsilon.h>
#include <spicy/compiler/detail/codegen/productions/look-ahead.h>
#include <spicy/compiler/detail/codegen/productions/reference.h>
#include <spicy/compiler/detail/codegen/productions/sequence.h>
#include <spicy/compiler/detail/codegen/productions/while.h>

using namespace spicy;
using namespace spicy::detail;
using namespace spicy::detail::codegen;

production::While::While(const std::string& symbol, std::unique_ptr<Production> body, const Location& l)
    : Production(symbol, l), _body(std::move(body)) {}

std::string production::While::dump() const {
    if ( _expression )
        return hilti::util::fmt("while(%s): %s", *_expression, _body->symbol());
    else
        return hilti::util::fmt("while(<look-ahead-found>): %s", _body->symbol());
}

void production::While::preprocessLookAhead(ASTContext* ctx, Grammar* grammar) {
    if ( _expression )
        hilti::logger().internalError("preprocessLookAhead() must be called only for a look-ahead loop");

    // We wrap the body into an additional little grammar that reflects the
    // loop, so that computation of look-ahead symbols will work correctly.
    // Specifically:
    //
    //      List1 -> Epsilon | List2
    //      List2 -> Item List1
    //
    // This is Left-factored & right-recursive.
    auto unresolved = std::make_unique<production::Deferred>(ctx);
    auto unresolved_ptr = unresolved.get();

    auto l1 = std::make_unique<production::LookAhead>(ctx, symbol() + "_l1",
                                                      std::make_unique<production::Epsilon>(ctx, location()),
                                                      std::move(unresolved), nullptr, location());
    auto l1_ref = std::make_unique<production::Reference>(ctx, l1.get());

    auto body_ref = std::make_unique<production::Reference>(ctx, _body.get());
    std::vector<std::unique_ptr<Production>> l2_prods;
    l2_prods.emplace_back(std::move(body_ref));
    l2_prods.emplace_back(std::move(l1_ref));
    auto l2 = std::make_unique<production::Sequence>(ctx, symbol() + "_l2", std::move(l2_prods), location());

    grammar->resolve(unresolved_ptr, std::move(l2));

    _body_for_grammar = std::move(l1);
}
