// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <utility>

#include <spicy/compiler/detail/codegen/grammar.h>
#include <spicy/compiler/detail/codegen/production.h>
#include <spicy/compiler/detail/codegen/productions/epsilon.h>
#include <spicy/compiler/detail/codegen/productions/look-ahead.h>
#include <spicy/compiler/detail/codegen/productions/resolved.h>
#include <spicy/compiler/detail/codegen/productions/sequence.h>
#include <spicy/compiler/detail/codegen/productions/while.h>

using namespace spicy;
using namespace spicy::detail;
using namespace spicy::detail::codegen;

production::While::While(const std::string& symbol, Production body, const Location& l)
    : ProductionBase(symbol, l), _body(std::move(body)) {}

std::string production::While::render() const {
    if ( _expression )
        return hilti::util::fmt("while(%s): %s", *_expression, _body.symbol());
    else
        return hilti::util::fmt("while(<look-ahead-found>): %s", _body.symbol());
}

void production::While::preprocessLookAhead(Grammar* grammar) {
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
    auto x = production::Unresolved();
    auto l1 = production::LookAhead(symbol() + "_l1", production::Epsilon(location()), x, location());
    auto l2 = production::Sequence(symbol() + "_l2", {_body, l1}, location());
    grammar->resolve(&x, std::move(l2));
    _body_for_grammar = std::move(l1);
}
