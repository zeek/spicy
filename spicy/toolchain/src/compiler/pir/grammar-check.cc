// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <map>
#include <set>
#include <string>

#include <hilti/base/util.h>

#include <spicy/ast/types/unit-items/field.h>
#include <spicy/compiler/detail/codegen/grammar.h>
#include <spicy/compiler/detail/codegen/productions/all.h>
#include <spicy/compiler/detail/pir/lowerer.h>

using namespace spicy;
using namespace spicy::detail;
using hilti::util::fmt;

namespace {

// Tokens are the same if they print the same, as for legacy.
std::string tokenKey(const codegen::Production* token) { return token->follow()->dump(); }

std::string tokenName(const codegen::Production* token) {
    if ( auto* expr = token->follow()->expression() )
        return fmt("'%s'", *expr);
    return fmt("'%s'", token->follow()->dump());
}

} // namespace

std::vector<pir::ir::Diagnostic> pir::checkLookAheads(const codegen::Grammar& grammar, ir::Package& package) {
    std::vector<ir::Diagnostic> diags;
    ir::DiagnosticEmitter emitter(package, diags);

    // A loop owns its look-ahead. Any other look-ahead decides between the cases of a switch.
    std::map<const codegen::production::LookAhead*, const type::unit::item::Field*> loops;
    for ( const auto& [_, production] : grammar.productions() ) {
        const auto* loop = production->tryAs<codegen::production::While>();
        if ( loop && ! loop->expression() )
            loops[loop->lookAheadProduction()] = loop->meta().field();
    }

    for ( const auto& [_, production] : grammar.productions() ) {
        const auto* lap = production->tryAs<codegen::production::LookAhead>();
        if ( ! lap )
            continue;

        auto loop = loops.find(lap);
        const auto* field = loop != loops.end() ? loop->second : nullptr;
        auto span = internSpan(package, field ? field->meta().location() : lap->location());
        auto what = field ? fmt("field '%s'", field->id()) : std::string("this switch case");

        const auto& [first, second] = lap->lookAheads();
        if ( first.empty() && second.empty() ) {
            emitter.emit(ir::diag::NoLookAhead, span, what);
            continue;
        }

        bool non_terminal = false;
        for ( const auto* token : hilti::util::setUnion(first, second) ) {
            if ( ! token->isTerminal() ) {
                emitter.emit(ir::diag::NonTerminalLookAhead, span, what, token->symbol());
                non_terminal = true;
                break;
            }
        }

        if ( non_terminal )
            continue;

        std::map<std::string, const codegen::Production*> first_keys;
        for ( const auto* token : first )
            first_keys.emplace(tokenKey(token), token);

        for ( const auto* token : second ) {
            auto other = first_keys.find(tokenKey(token));
            if ( other == first_keys.end() )
                continue;

            // The first alternative of a loop is what follows it, the second its body.
            auto name = tokenName(token);
            auto diag = field ? emitter.emit(ir::diag::AmbiguousLoopEnd, span, std::string(field->id()), name) :
                                emitter.emit(ir::diag::AmbiguousSwitchCase, span, name);
            diag.note(ir::diag::LookAheadTokenHere,
                      internSpan(package, token->location()),
                      name,
                      field ? "an element" : "this case");
            diag.note(ir::diag::LookAheadTokenHere,
                      internSpan(package, other->second->location()),
                      name,
                      field ? "what follows" : "an earlier case");
        }
    }

    return diags;
}
