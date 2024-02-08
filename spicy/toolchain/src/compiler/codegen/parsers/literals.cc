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
    LiteralParser(ParserBuilder* pb, const Production* p, ExpressionPtr dst)
        : pb(pb), production(p), dst(std::move(dst)) {}

    ParserBuilder* pb;
    const Production* production;
    const ExpressionPtr dst;

    ExpressionPtr buildParser(const NodePtr& n);

    ExpressionPtr destination(const UnqualifiedTypePtr& t) {
        if ( dst )
            return dst;

        if ( auto field = production->meta().field() )
            return pb->builder()->addTmp("c", field->parseType());

        return pb->builder()->addTmp("c", pb->builder()->qualifiedType(t, hilti::Constness::NonConst));
    }
};

struct Visitor : public visitor::PreOrder {
    Visitor(LiteralParser* lp) : lp(lp) {}

    LiteralParser* lp;
    ExpressionPtr result = nullptr;

    auto pb() { return lp->pb; }
    auto state() { return pb()->state(); }
    auto builder() { return pb()->builder(); }
    auto context() { return pb()->context(); }
    auto pushBuilder(std::shared_ptr<Builder> b) { return pb()->pushBuilder(std::move(b)); }
    auto pushBuilder() { return pb()->pushBuilder(); }
    auto pushBuilder(std::shared_ptr<Builder> b, const std::function<void()>& func) {
        return pb()->pushBuilder(std::move(b), func);
    }
    auto popBuilder() { return pb()->popBuilder(); }

    void operator()(hilti::ctor::Bytes* n) final {
        auto error_msg = fmt("expecting '%s'", n->value());
        auto len = builder()->integer(static_cast<uint64_t>(n->value().size()));
        auto cond =
            builder()->memberCall(state().cur, "starts_with", {builder()->expression(n->as<hilti::ctor::Bytes>())});

        switch ( state().literal_mode ) {
            case LiteralMode::Default:
            case LiteralMode::Skip: {
                auto [have_lah, no_lah] = builder()->addIfElse(state().lahead);

                pushBuilder(have_lah);

                pushBuilder(builder()->addIf(
                    builder()->unequal(state().lahead, builder()->integer(lp->production->tokenID()))));
                pb()->parseError("unexpected token to consume", n->meta());
                popBuilder();

                pushBuilder(builder()->addIf(
                    builder()->unequal(builder()->expression(n->as<hilti::ctor::Bytes>()),
                                       builder()->memberCall(state().cur, "sub",
                                                             {builder()->begin(state().cur), state().lahead_end}))));
                pb()->parseError("unexpected data when consuming token", n->meta());
                popBuilder();

                pb()->consumeLookAhead();
                popBuilder();

                pushBuilder(no_lah);
                pb()->waitForInput(len, error_msg, n->meta());
                auto no_match = builder()->addIf(builder()->not_(cond));
                pushBuilder(no_match);
                pb()->parseError(error_msg, n->meta());
                popBuilder();

                pb()->advanceInput(len);
                popBuilder();

                if ( state().literal_mode != LiteralMode::Skip )
                    builder()->addAssign(lp->destination(n->type()->type()),
                                         builder()->expression(n->as<hilti::ctor::Bytes>()));

                result = builder()->expression(n->as<hilti::ctor::Bytes>());
                return;
            }

            case LiteralMode::Search: // Handled in `parseLiteral`.
            case LiteralMode::Try:
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

        auto parse = [&](ExpressionPtr result) -> ExpressionPtr {
            auto [have_lah, no_lah] = builder()->addIfElse(state().lahead);
            if ( ! result && state().literal_mode != LiteralMode::Skip )
                result = lp->destination(builder()->typeBytes());

            pushBuilder(have_lah);

            pushBuilder(
                builder()->addIf(builder()->unequal(state().lahead, builder()->integer(lp->production->tokenID()))));
            pb()->parseError("unexpected token to consume", n->meta());
            popBuilder();

            pb()->consumeLookAhead(result);
            popBuilder();

            pushBuilder(no_lah);

            builder()->addLocal(ID("ncur"), state().cur);
            auto ms = builder()->local("ms", builder()->memberCall(builder()->id(re), "token_matcher"));
            auto body = builder()->addWhile(ms, builder()->bool_(true));
            pushBuilder(body);

            builder()->addLocal(ID("rc"),
                                builder()->qualifiedType(builder()->typeSignedInteger(32), hilti::Constness::NonConst));

            builder()->addAssign(builder()->tuple({builder()->id("rc"), builder()->id("ncur")}),
                                 builder()->memberCall(builder()->id("ms"), "advance", {builder()->id("ncur")}),
                                 n->meta());

            auto switch_ = builder()->addSwitch(builder()->id("rc"), n->meta());

            auto no_match_try_again = switch_.addCase(builder()->integer(-1));
            pushBuilder(no_match_try_again);
            auto pstate = pb()->state();
            pstate.self = builder()->expressionName(ID("self"));
            pstate.cur = builder()->id("ncur");
            pb()->pushState(std::move(pstate));

            builder()->addComment("NOLINTNEXTLINE(clang-analyzer-deadcode.DeadStores)");
            builder()->addLocal(ID("more_data"), pb()->waitForInputOrEod());

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
                    builder()->addAssign(*state().captures,
                                         builder()->memberCall(builder()->id("ms"), "captures", {state().data}));

                builder()->addAssign(result, builder()->memberCall(state().cur, "sub",
                                                                   {builder()->begin(builder()->id("ncur"))}));
            }

            pb()->setInput(builder()->id("ncur"));
            builder()->addBreak();
            popBuilder();

            popBuilder();

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

    ExpressionPtr parseInteger(const UnqualifiedTypePtr& type, const ExpressionPtr& expected, const Meta& meta) {
        auto offset = [this](ExpressionPtr view) { return builder()->memberCall(std::move(view), "offset"); };

        switch ( state().literal_mode ) {
            case LiteralMode::Default:
            case LiteralMode::Skip: {
                auto [have_lah, no_lah] = builder()->addIfElse(state().lahead);

                pushBuilder(have_lah);

                pushBuilder(builder()->addIf(
                    builder()->unequal(state().lahead, builder()->integer(lp->production->tokenID()))));
                pb()->parseError("unexpected token to consume", meta);
                popBuilder();

                pb()->consumeLookAhead();
                popBuilder();

                pushBuilder(no_lah);
                auto old_cur = builder()->addTmp("ocur", state().cur);

                // Parse value as an instance of the corresponding type.
                auto x = pb()->parseType(type, lp->production->meta(), {});

                // Compare parsed value against expected value.
                auto no_match = builder()->or_(builder()->equal(offset(old_cur), offset(state().cur)),
                                               builder()->unequal(x, expected));

                auto error = builder()->addIf(no_match);
                pushBuilder(error);
                builder()->addAssign(state().cur, old_cur);
                pb()->parseError(fmt("expecting %u", *expected), meta);
                popBuilder();

                popBuilder();

                if ( state().literal_mode != LiteralMode::Skip )
                    builder()->addAssign(lp->destination(type), expected);

                return expected;
            }

            case LiteralMode::Search: // Handled in `parseLiteral`.
            case LiteralMode::Try: {
                auto old_cur = builder()->addTmp("ocur", state().cur);
                auto x = pb()->parseTypeTry(type, lp->production->meta(), {});
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
        result =
            parseInteger(n->type()->type(), builder()->expression(n->as<hilti::ctor::UnsignedInteger>()), n->meta());
    }

    void operator()(hilti::ctor::SignedInteger* n) final {
        result = parseInteger(n->type()->type(), builder()->expression(n->as<hilti::ctor::SignedInteger>()), n->meta());
    }

    void operator()(hilti::ctor::Bitfield* n) final {
        auto offset = [this](ExpressionPtr view) { return builder()->memberCall(std::move(view), "offset"); };

        switch ( state().literal_mode ) {
            case LiteralMode::Default:
            case LiteralMode::Skip: {
                auto [have_lah, no_lah] = builder()->addIfElse(state().lahead);

                pushBuilder(have_lah);

                pushBuilder(builder()->addIf(
                    builder()->unequal(state().lahead, builder()->integer(lp->production->tokenID()))));
                pb()->parseError("unexpected token to consume", n->meta());
                popBuilder();

                // Need to reparse the value to assign it to our destination.
                auto value = pb()->parseType(n->btype(), lp->production->meta(), {});
                builder()->addAssign(lp->destination(n->btype()), value);

                pb()->consumeLookAhead();
                popBuilder();

                pushBuilder(no_lah);
                auto old_cur = builder()->addTmp("ocur", state().cur);

                value = pb()->parseType(n->btype(), lp->production->meta(), {});

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

                popBuilder();

                result = value;
                return;
            }

            case LiteralMode::Search: // Handled in `parseLiteral`.
            case LiteralMode::Try: {
                auto old_cur = builder()->addTmp("ocur", state().cur);
                auto bf = builder()->addTmp("bf", n->btype());
                pb()->parseTypeTry(n->btype(), lp->production->meta(), bf);
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

ExpressionPtr LiteralParser::buildParser(const NodePtr& n) {
    return hilti::visitor::dispatch(Visitor(this), n, [](const auto& v) { return v.result; });
}

} // namespace

ExpressionPtr ParserBuilder::parseLiteral(const Production& p, const ExpressionPtr& dst) {
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
