// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <utility>

#include <hilti/ast/builder/builder.h>
#include <hilti/ast/expressions/ctor.h>
#include <hilti/base/logger.h>

#include <spicy/ast/builder/builder.h>
#include <spicy/ast/types/unit-items/field.h>
#include <spicy/compiler/detail/codegen/codegen.h>
#include <spicy/compiler/detail/codegen/parser-builder.h>

using namespace spicy;
using namespace spicy::detail;
using namespace spicy::detail::codegen;
using hilti::util::fmt;

namespace {

struct LiteralParser {
    LiteralParser(ParserBuilder* pb, const Production* p, Expression* dst) : pb(pb), production(p), dst(dst) {}

    ParserBuilder* pb;
    const Production* production;
    Expression* dst = nullptr;

    Expression* buildParser(Node* n);

    Expression* destination(UnqualifiedType* t) {
        if ( dst )
            return dst;

        if ( auto field = production->meta().field() )
            return pb->builder()->addTmp("c", field->parseType());

        return pb->builder()->addTmp("c", pb->builder()->qualifiedType(t, hilti::Constness::Mutable));
    }
};

struct Visitor : public visitor::PreOrder {
    Visitor(LiteralParser* lp) : lp(lp) {}

    LiteralParser* lp;
    Expression* result = nullptr;

    auto pb() { return lp->pb; }
    auto state() { return pb()->state(); }
    auto builder() { return pb()->builder(); }
    auto context() { return pb()->context(); }
    auto pushBuilder(std::shared_ptr<Builder> b) { return pb()->pushBuilder(std::move(b)); }
    auto pushBuilder() { return pb()->pushBuilder(); }
    template<typename Func>
    auto pushBuilder(std::shared_ptr<Builder> b, Func&& func) {
        return pb()->pushBuilder(std::move(b), std::forward(func));
    }
    auto popBuilder() { return pb()->popBuilder(); }

    auto needToCheckForLookAhead(const Meta& meta) {
        bool needs_check = false;

        if ( auto field = lp->production->meta().field(); field && field->attributes()->find("&synchronize") )
            needs_check = true;
        else {
            auto tokens = pb()->cg()->astInfo().look_aheads_in_use;
            needs_check = tokens.find(lp->production->tokenID()) != tokens.end();
        }

        if ( pb()->options().debug && ! needs_check )
            builder()->addAssert(builder()->not_(state().lahead), "unexpected look-ahead token pending", meta);

        return needs_check;
    }

    void operator()(hilti::ctor::Bytes* n) final {
        auto len = builder()->integer(static_cast<uint64_t>(n->value().size()));

        switch ( state().literal_mode ) {
            case LiteralMode::Default:
            case LiteralMode::Skip: {
                bool check_for_look_ahead = needToCheckForLookAhead(n->meta());
                if ( check_for_look_ahead ) {
                    auto [have_lah, no_lah] = builder()->addIfElse(state().lahead);

                    pushBuilder(have_lah);

                    pushBuilder(builder()->addIf(
                        builder()->unequal(state().lahead, builder()->integer(lp->production->tokenID()))));
                    pb()->parseError("unexpected token to consume", n->meta());
                    popBuilder();

                    auto literal = builder()->addTmp("literal", builder()->expression(n));

                    pushBuilder(builder()->addIf(
                        builder()->unequal(literal, builder()->memberCall(state().cur, "sub",
                                                                          {builder()->begin(state().cur),
                                                                           state().lahead_end}))));
                    pb()->parseError("unexpected data when consuming token", n->meta());
                    popBuilder();

                    builder()->addAssign(lp->destination(n->type()->type()), literal);

                    pb()->consumeLookAhead();
                    popBuilder();

                    pushBuilder(no_lah);
                }

                auto expect_bytes_literal =
                    builder()->call("spicy_rt::expectBytesLiteral",
                                    {state().data, state().cur, builder()->expression(n),
                                     builder()->expression(n->meta()), pb()->currentFilters(state())});


                if ( state().literal_mode != LiteralMode::Skip )
                    builder()->addAssign(lp->destination(n->type()->type()), expect_bytes_literal);
                else
                    builder()->addExpression(expect_bytes_literal);

                pb()->advanceInput(len);

                if ( check_for_look_ahead )
                    popBuilder();

                result = builder()->expression(n);
                return;
            }

            case LiteralMode::Search: // Handled in `parseLiteral`.
            case LiteralMode::Try:
                auto cond = builder()->memberCall(state().cur, "starts_with", {builder()->expression(n)});
                result = builder()->ternary(builder()->and_(pb()->waitForInputOrEod(len), cond),
                                            builder()->sum(builder()->begin(state().cur), len),
                                            builder()->begin(state().cur));
                return;
        }

        hilti::util::cannotBeReached();
    }

    void operator()(hilti::ctor::RegExp* n) final {
        auto re = hilti::ID(fmt("__re_%" PRId64, lp->production->tokenID()));

        if ( ! pb()->cg()->haveAddedDeclaration(re) ) {
            auto attrs = builder()->attributeSet({builder()->attribute("&anchor")});

            if ( ! state().captures )
                attrs->add(context(), builder()->attribute("&nosub"));

            auto d = builder()->constant(re, builder()->regexp(n->value(), attrs));
            pb()->cg()->addDeclaration(d);
        }

        auto parse = [&](Expression* result) -> Expression* {
            if ( ! result && state().literal_mode != LiteralMode::Skip )
                result = lp->destination(builder()->typeBytes());

            bool check_for_look_ahead = needToCheckForLookAhead(n->meta());
            if ( check_for_look_ahead ) {
                auto [have_lah, no_lah] = builder()->addIfElse(state().lahead);

                pushBuilder(have_lah);

                pushBuilder(builder()->addIf(
                    builder()->unequal(state().lahead, builder()->integer(lp->production->tokenID()))));
                pb()->parseError("unexpected token to consume", n->meta());
                popBuilder();

                pb()->consumeLookAhead(result);
                popBuilder();

                pushBuilder(no_lah);
            }

            auto ncur = builder()->addTmp(ID("ncur"), state().cur);
            auto ms = builder()->local("ms", builder()->memberCall(builder()->id(re), "token_matcher"));
            auto body = builder()->addWhile(ms, builder()->bool_(true));
            pushBuilder(body);

            auto rc = builder()->addTmp(ID("rc"), builder()->qualifiedType(builder()->typeSignedInteger(32),
                                                                           hilti::Constness::Mutable));

            builder()->addAssign(builder()->tuple({rc, ncur}),
                                 builder()->memberCall(builder()->id("ms"), "advance", {ncur}), n->meta());

            auto switch_ = builder()->addSwitch(rc, n->meta());

            auto no_match_try_again = switch_.addCase(builder()->integer(-1));
            pushBuilder(no_match_try_again);
            auto pstate = pb()->state();
            pstate.self = builder()->expressionName(ID("self"));
            pstate.cur = ncur;
            pb()->pushState(std::move(pstate));

            builder()->addComment("NOLINTNEXTLINE(clang-analyzer-deadcode.DeadStores)");
            builder()->addExpression(pb()->waitForInputOrEod());

            pb()->popState();
            builder()->addContinue();
            popBuilder();

            auto no_match_error = switch_.addCase(builder()->integer(0));
            pushBuilder(no_match_error);
            pb()->parseError("failed to match regular expression", n->meta());
            popBuilder();

            auto match = switch_.addDefault();
            pushBuilder(match);

            if ( state().literal_mode != LiteralMode::Skip ) {
                if ( state().captures )
                    builder()->addAssign(state().captures,
                                         builder()->memberCall(builder()->id("ms"), "captures", {state().data}));

                builder()->addAssign(result, builder()->memberCall(state().cur, "sub", {builder()->begin(ncur)}));
            }

            pb()->setInput(ncur);
            builder()->addBreak();
            popBuilder();

            popBuilder();

            if ( check_for_look_ahead )
                popBuilder();

            return result;
        };

        switch ( state().literal_mode ) {
            case LiteralMode::Default:
            case LiteralMode::Skip: {
                result = parse(result);
                return;
            }

            case LiteralMode::Search: // Handled in `parseLiteral`.
            case LiteralMode::Try: {
                auto tmp = builder()->addTmp("result", state().cur);
                result = parse(tmp);
                return;
            }
        }

        hilti::util::cannotBeReached();
    }

    void operator()(hilti::expression::Ctor* n) final { result = lp->buildParser(n->ctor()); }

    Expression* parseInteger(UnqualifiedType* type, Expression* expected, const Meta& meta) {
        auto offset = [this](Expression* view) { return builder()->memberCall(view, "offset"); };

        switch ( state().literal_mode ) {
            case LiteralMode::Default:
            case LiteralMode::Skip: {
                bool check_for_look_ahead = needToCheckForLookAhead(meta);
                if ( check_for_look_ahead ) {
                    auto [have_lah, no_lah] = builder()->addIfElse(state().lahead);

                    pushBuilder(have_lah);

                    pushBuilder(builder()->addIf(
                        builder()->unequal(state().lahead, builder()->integer(lp->production->tokenID()))));
                    pb()->parseError("unexpected token to consume", meta);
                    popBuilder();

                    pb()->consumeLookAhead();
                    popBuilder();

                    pushBuilder(no_lah);
                }

                auto old_cur = builder()->addTmp("ocur", state().cur);

                // Parse value as an instance of the corresponding type, without trimming.
                auto x = pb()->parseType(type, lp->production->meta(), {}, TypesMode::Default, true);

                // Compare parsed value against expected value.
                auto no_match = builder()->or_(builder()->equal(offset(old_cur), offset(state().cur)),
                                               builder()->unequal(x, expected));

                auto error = builder()->addIf(no_match);
                pushBuilder(error);
                builder()->addAssign(state().cur, old_cur);
                pb()->parseError(fmt("expecting %u", *expected), meta);
                popBuilder();

                if ( check_for_look_ahead )
                    popBuilder();

                if ( state().literal_mode != LiteralMode::Skip )
                    builder()->addAssign(lp->destination(type), expected);

                pb()->trimInput();

                return expected;
            }

            case LiteralMode::Search: // Handled in `parseLiteral`.
            case LiteralMode::Try: {
                auto old_cur = builder()->addTmp("ocur", state().cur);
                auto x = pb()->parseType(type, lp->production->meta(), {}, TypesMode::Try);
                auto new_cur = builder()->addTmp("ncur", state().cur);
                builder()->addAssign(state().cur, old_cur);

                // Compare parsed value against expected value.
                auto match = builder()->and_(x, builder()->and_(builder()->unequal(offset(old_cur), offset(new_cur)),
                                                                builder()->equal(builder()->deref(x), expected)));
                return builder()->begin(builder()->ternary(match, new_cur, old_cur));
            }
        }

        hilti::util::cannotBeReached();
    }

    void operator()(hilti::ctor::UnsignedInteger* n) final {
        result = parseInteger(n->type()->type(), builder()->expression(n), n->meta());
    }

    void operator()(hilti::ctor::SignedInteger* n) final {
        result = parseInteger(n->type()->type(), builder()->expression(n), n->meta());
    }

    void operator()(hilti::ctor::Bitfield* n) final {
        auto offset = [this](Expression* view) { return builder()->memberCall(view, "offset"); };

        switch ( state().literal_mode ) {
            case LiteralMode::Default:
            case LiteralMode::Skip: {
                bool check_for_look_ahead = needToCheckForLookAhead(n->meta());
                if ( check_for_look_ahead ) {
                    auto [have_lah, no_lah] = builder()->addIfElse(state().lahead);

                    pushBuilder(have_lah);

                    pushBuilder(builder()->addIf(
                        builder()->unequal(state().lahead, builder()->integer(lp->production->tokenID()))));
                    pb()->parseError("unexpected token to consume", n->meta());
                    popBuilder();

                    // Need to reparse the value to assign it to our destination.
                    auto value = pb()->parseType(n->btype(), lp->production->meta(), {}, TypesMode::Default);
                    builder()->addAssign(lp->destination(n->btype()), value);

                    pb()->consumeLookAhead();
                    popBuilder();

                    pushBuilder(no_lah);
                }

                auto old_cur = builder()->addTmp("ocur", state().cur);

                // Parse value as an instance of the underlying type, without trimming.
                auto value = pb()->parseType(n->btype(), lp->production->meta(), {}, TypesMode::Default, true);

                // Check that the bit values match what we expect.
                for ( const auto& b : n->bits() ) {
                    auto error =
                        builder()->addIf(builder()->unequal(builder()->member(value, b->id()), b->expression()));
                    pushBuilder(error);
                    builder()->addAssign(state().cur, old_cur);
                    pb()->parseError(fmt("unexpected value for bitfield element '%s'", b->id()), n->meta());
                    popBuilder();
                }

                if ( state().literal_mode != LiteralMode::Skip )
                    builder()->addAssign(lp->destination(n->btype()), value);

                pb()->trimInput();

                if ( check_for_look_ahead )
                    popBuilder();

                result = value;
                return;
            }

            case LiteralMode::Search: // Handled in `parseLiteral`.
            case LiteralMode::Try: {
                auto old_cur = builder()->addTmp("ocur", state().cur);
                auto bf = builder()->addTmp("bf", n->btype());
                pb()->parseType(n->btype(), lp->production->meta(), bf, TypesMode::Try);
                auto new_cur = builder()->addTmp("ncur", state().cur);

                auto match = builder()->addIf(builder()->unequal(offset(old_cur), offset(new_cur)));
                pushBuilder(match);
                builder()->addAssign(state().cur, old_cur); // restore, because we must not move cur when in sync mode

                // Check that the bit values match what we expect.
                for ( const auto& b : n->bits() ) {
                    auto error = builder()->addIf(builder()->unequal(builder()->member(bf, b->id()), b->expression()));
                    pushBuilder(error);
                    builder()->addAssign(new_cur, old_cur); // reset to old position
                    popBuilder();
                }

                popBuilder();

                result = builder()->begin(new_cur);
                return;
            }
        }

        hilti::util::cannotBeReached();
    }
};

Expression* LiteralParser::buildParser(Node* n) {
    return hilti::visitor::dispatch(Visitor(this), n, [](const auto& v) { return v.result; });
}

} // namespace

Expression* ParserBuilder::parseLiteral(const Production& p, Expression* dst) {
    if ( auto e = LiteralParser(this, &p, dst).buildParser(p.expression()) )
        return e;

    hilti::logger().internalError(fmt("codegen: literal parser did not return expression for '%s'", *p.expression()));
}

void ParserBuilder::skipLiteral(const Production& p) {
    assert(p.isLiteral());

    auto pstate = state();
    pstate.literal_mode = LiteralMode::Skip;
    pushState(std::move(pstate));
    LiteralParser(this, &p, nullptr).buildParser(p.expression());
    popState();
}
