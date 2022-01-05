// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#include <utility>

#include <hilti/ast/builder/all.h>
#include <hilti/base/logger.h>

#include <spicy/ast/aliases.h>
#include <spicy/ast/detail/visitor.h>
#include <spicy/ast/types/unit-items/field.h>
#include <spicy/compiler/detail/codegen/codegen.h>
#include <spicy/compiler/detail/codegen/parser-builder.h>

using namespace spicy;
using namespace spicy::detail;
using namespace spicy::detail::codegen;
using hilti::util::fmt;

namespace builder = hilti::builder;

namespace {

struct Visitor : public hilti::visitor::PreOrder<Expression, Visitor> {
    Visitor(ParserBuilder* pb, const Production& p, const std::optional<Expression>& dst)
        : pb(pb), production(p), dst(dst) {}
    ParserBuilder* pb;
    const Production& production;
    const std::optional<Expression>& dst;

    auto state() { return pb->state(); }
    auto builder() { return pb->builder(); }
    auto pushBuilder(std::shared_ptr<builder::Builder> b) { return pb->pushBuilder(std::move(b)); }
    auto pushBuilder() { return pb->pushBuilder(); }
    auto popBuilder() { return pb->popBuilder(); }

    Expression destination(const Type& t) {
        if ( dst )
            return *dst;

        if ( auto field = production.meta().field() )
            return builder()->addTmp("c", field->parseType());

        return builder()->addTmp("c", t);
    }

    result_t operator()(const hilti::ctor::Bytes& c) {
        auto error_msg = fmt("expecting '%s'", c.value());
        auto len = builder::integer(static_cast<uint64_t>(c.value().size()));
        auto cond = builder::memberCall(state().cur, "starts_with", {builder::expression(c)});

        switch ( state().literal_mode ) {
            case LiteralMode::Default: {
                auto [have_lah, no_lah] = builder()->addIfElse(state().lahead);

                pushBuilder(have_lah);
                builder()->addAssert(builder::equal(state().lahead, builder::integer(production.tokenID())),
                                     "unexpected token to consume");
                builder()->addAssert(hilti::builder::equal(builder::expression(c),
                                                           builder::memberCall(state().cur, "sub",
                                                                               {builder::begin(state().cur),
                                                                                state().lahead_end})),
                                     "unexpected data when consuming token");
                pb->consumeLookAhead();
                popBuilder();

                pushBuilder(no_lah);
                pb->waitForInput(len, error_msg, c.meta());
                auto no_match = builder()->addIf(builder::not_(cond));
                pushBuilder(no_match);
                pb->parseError(error_msg, c.meta());
                popBuilder();

                pb->advanceInput(len);
                popBuilder();

                builder()->addAssign(destination(c.type()), builder::expression(c));
                return builder::expression(c);
            }

            case LiteralMode::Search: // Handled in `parseLiteral`.
            case LiteralMode::Try:
                return builder::ternary(builder::and_(pb->waitForInputOrEod(len), cond),
                                        builder::sum(builder::begin(state().cur), len), builder::begin(state().cur));
        }
    }

    result_t operator()(const hilti::ctor::RegExp& c) {
        auto re = hilti::ID(fmt("__re_%" PRId64, production.tokenID()));

        if ( ! pb->cg()->haveAddedDeclaration(re) ) {
            auto attrs = AttributeSet({Attribute("&anchor")});

            if ( ! state().captures )
                attrs = AttributeSet::add(attrs, Attribute("&nosub"));

            auto d = builder::constant(re, builder::regexp(c.value(), std::move(attrs)));
            pb->cg()->addDeclaration(d);
        }

        switch ( state().literal_mode ) {
            case LiteralMode::Default: {
                auto [have_lah, no_lah] = builder()->addIfElse(state().lahead);
                auto dst = destination(type::Bytes());

                pushBuilder(have_lah);
                builder()->addAssert(builder::equal(state().lahead, builder::integer(production.tokenID())),
                                     "unexpected token to consume");
                pb->consumeLookAhead(dst);
                popBuilder();

                pushBuilder(no_lah);

                builder()->addLocal(ID("ncur"), state().cur);
                auto ms = builder::local("ms", builder::memberCall(builder::id(re), "token_matcher", {}));
                auto body = builder()->addWhile(ms, builder::bool_(true));
                pushBuilder(body);

                builder()->addLocal(ID("rc"), hilti::type::SignedInteger(32));

                builder()->addAssign(builder::tuple({builder::id("rc"), builder::id("ncur")}),
                                     builder::memberCall(builder::id("ms"), "advance", {builder::id("ncur")}),
                                     c.meta());

                auto switch_ = builder()->addSwitch(builder::id("rc"), c.meta());

                auto no_match_try_again = switch_.addCase(builder::integer(-1));
                pushBuilder(no_match_try_again);
                auto pstate = pb->state();
                pstate.self = hilti::expression::UnresolvedID(ID("self"));
                pstate.cur = builder::id("ncur");
                pb->pushState(std::move(pstate));

                builder()->addComment("NOLINTNEXTLINE(clang-analyzer-deadcode.DeadStores)");
                builder()->addLocal(ID("more_data"), pb->waitForInputOrEod());

                pb->popState();
                builder()->addContinue();
                popBuilder();

                auto no_match_error = switch_.addCase(builder::integer(0));
                pushBuilder(no_match_error);
                pb->parseError("failed to match regular expression", c.meta());
                popBuilder();

                auto match = switch_.addDefault();
                pushBuilder(match);

                if ( state().captures )
                    builder()->addAssign(*state().captures,
                                         builder::memberCall(builder::id("ms"), "captures", {state().data}));

                builder()->addAssign(dst,
                                     builder::memberCall(state().cur, "sub", {builder::begin(builder::id("ncur"))}));
                pb->setInput(builder::id("ncur"));
                builder()->addBreak();
                popBuilder();

                popBuilder();

                popBuilder();

                return dst;
            }

            case LiteralMode::Search: // Handled in `parseLiteral`.
            case LiteralMode::Try: {
                auto result = builder()->addTmp("result", state().cur);

                auto [have_lah, no_lah] = builder()->addIfElse(state().lahead);

                pushBuilder(have_lah);
                builder()->addAssert(builder::equal(state().lahead, builder::integer(production.tokenID())),
                                     "unexpected token to consume");
                pb->consumeLookAhead();
                builder()->addAssign(result, state().cur);

                popBuilder();

                pushBuilder(no_lah);

                builder()->addLocal(ID("ncur"), state().cur);
                auto ms = builder::local("ms", builder::memberCall(builder::id(re), "token_matcher", {}));
                auto body = builder()->addWhile(ms, builder::bool_(true));
                pushBuilder(body);

                builder()->addLocal(ID("rc"), hilti::type::SignedInteger(32));

                builder()->addAssign(builder::tuple({builder::id("rc"), builder::id("ncur")}),
                                     builder::memberCall(builder::id("ms"), "advance", {builder::id("ncur")}),
                                     c.meta());

                auto switch_ = builder()->addSwitch(builder::id("rc"), c.meta());

                auto no_match_try_again = switch_.addCase(builder::integer(-1));
                pushBuilder(no_match_try_again);
                auto pstate = pb->state();
                pstate.self = hilti::expression::UnresolvedID(ID("self"));
                pstate.cur = builder::id("ncur");
                pb->pushState(std::move(pstate));

                builder()->addComment("NOLINTNEXTLINE(clang-analyzer-deadcode.DeadStores)");
                builder()->addLocal(ID("more_data"), pb->waitForInputOrEod());

                pb->popState();
                builder()->addContinue();
                popBuilder();

                auto no_match_error = switch_.addCase(builder::integer(0));
                pushBuilder(no_match_error);
                pb->parseError("failed to match regular expression", c.meta());
                popBuilder();

                auto match = switch_.addDefault();
                pushBuilder(match);

                if ( state().captures )
                    builder()->addAssign(*state().captures,
                                         builder::memberCall(builder::id("ms"), "captures", {state().data}));

                pb->setInput(builder::id("ncur"));
                builder()->addAssign(result, state().cur);
                builder()->addBreak();
                popBuilder();

                popBuilder();

                popBuilder();

                return result;
            }
        }
    }

    result_t operator()(const hilti::expression::Ctor& c) { return *dispatch(c.ctor()); }

    result_t parseInteger(const Type& type, const Expression& expected, const Meta& meta) {
        auto offset = [](Expression view) { return builder::memberCall(view, "offset", {}); };

        switch ( state().literal_mode ) {
            case LiteralMode::Default: {
                auto [have_lah, no_lah] = builder()->addIfElse(state().lahead);

                pushBuilder(have_lah);
                builder()->addAssert(builder::equal(state().lahead, builder::integer(production.tokenID())),
                                     "unexpected token to consume");
                pb->consumeLookAhead();
                popBuilder();

                pushBuilder(no_lah);
                auto old_cur = builder()->addTmp("ocur", state().cur);

                // Parse value as an instance of the corresponding type.
                auto x = pb->parseType(type, production.meta(), {});

                // Compare parsed value against expected value.
                auto no_match =
                    builder::or_(builder::equal(offset(old_cur), offset(state().cur)), builder::unequal(x, expected));

                auto error = builder()->addIf(no_match);
                pushBuilder(error);
                builder()->addAssign(state().cur, old_cur);
                pb->parseError(fmt("expecting %u", expected), meta);
                popBuilder();

                popBuilder();

                builder()->addAssign(destination(type), expected);
                return expected;
            }

            case LiteralMode::Search: // Handled in `parseLiteral`.
            case LiteralMode::Try: {
                auto old_cur = builder()->addTmp("ocur", state().cur);
                auto x = pb->parseTypeTry(type, production.meta(), {});
                auto new_cur = builder()->addTmp("ncur", state().cur);
                builder()->addAssign(state().cur, old_cur);

                // Compare parsed value against expected value.
                auto match = builder::and_(x, builder::and_(builder::unequal(offset(old_cur), offset(new_cur)),
                                                            builder::equal(builder::deref(x), expected)));
                return builder::begin(builder::ternary(match, new_cur, old_cur));
            }
        }
    }

    result_t operator()(const hilti::ctor::UnsignedInteger& c) {
        return parseInteger(c.type(), builder::expression(c), c.meta());
    }

    result_t operator()(const hilti::ctor::SignedInteger& c) {
        return parseInteger(c.type(), builder::expression(c), c.meta());
    }
};

} // namespace

Expression ParserBuilder::parseLiteral(const Production& p, const std::optional<Expression>& dst) {
    switch ( state().literal_mode ) {
        case LiteralMode::Default:
        case LiteralMode::Try: {
            if ( auto e = Visitor(this, p, dst).dispatch(p.expression()) )
                return std::move(*e);

            hilti::logger().internalError(
                fmt("codegen: literal parser did not return expression for '%s'", p.expression()));

            hilti::util::cannot_be_reached();
        }

        case LiteralMode::Search: break;
    }

    // The following code handles search mode.
    assert(state().literal_mode == LiteralMode::Search);

    // Set up return value.
    auto result = builder()->addTmp("result", builder::default_(type::Optional(type::stream::Iterator())));

    // Add a loop for search mode.
    pushBuilder(builder()->addWhile(builder::bool_(true)), [&]() {
        auto e = Visitor(this, p, dst).dispatch(p.expression());

        if ( ! e )
            hilti::logger().internalError(
                fmt("codegen: literal parser did not return expression for '%s'", p.expression()));
        builder()->addAssign(result, *e);

        switch ( state().literal_mode ) {
            case LiteralMode::Default:
            case LiteralMode::Try: {
                builder()->addBreak();
                break;
            }

            case LiteralMode::Search: {
                {
                    state().printDebug(builder());

                    pushBuilder(builder()->addIf(atEod()), [&]() { builder()->addBreak(); });

                    auto [if_, else_] = builder()->addIfElse(builder::unequal(*e, builder::begin(state().cur)));
                    pushBuilder(if_, [&]() { builder()->addBreak(); });
                    pushBuilder(else_, [&]() { advanceInput(builder::integer(1)); });
                };

                break;
            }
        }
    });

    if ( dst )
        builder()->addAssign(*dst, builder::deref(result));

    return builder::deref(result);
}
