// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <utility>

#include <hilti/ast/builder/all.h>
#include <hilti/ast/expressions/ctor.h>
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

struct Visitor : public hilti::visitor::PreOrder<std::optional<Expression>, Visitor> {
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
            case LiteralMode::Default:
            case LiteralMode::Skip: {
                auto [have_lah, no_lah] = builder()->addIfElse(state().lahead);

                pushBuilder(have_lah);

                pushBuilder(builder()->addIf(builder::unequal(state().lahead, builder::integer(production.tokenID()))));
                pb->parseError("unexpected token to consume", c.meta());
                popBuilder();

                pushBuilder(builder()->addIf(
                    hilti::builder::unequal(builder::expression(c),
                                            builder::memberCall(state().cur, "sub",
                                                                {builder::begin(state().cur), state().lahead_end}))));
                pb->parseError("unexpected data when consuming token", c.meta());
                popBuilder();

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

                if ( state().literal_mode != LiteralMode::Skip )
                    builder()->addAssign(destination(c.type()), builder::expression(c));

                return builder::expression(c);
            }

            case LiteralMode::Search: // Handled in `parseLiteral`.
            case LiteralMode::Try:
                return builder::ternary(builder::and_(pb->waitForInputOrEod(len), cond),
                                        builder::sum(builder::begin(state().cur), len), builder::begin(state().cur));
        }

        hilti::util::cannot_be_reached();
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

        auto parse = [&](std::optional<Expression> result) -> std::optional<Expression> {
            auto [have_lah, no_lah] = builder()->addIfElse(state().lahead);
            if ( ! result && state().literal_mode != LiteralMode::Skip )
                result = destination(type::Bytes());

            pushBuilder(have_lah);

            pushBuilder(builder()->addIf(builder::unequal(state().lahead, builder::integer(production.tokenID()))));
            pb->parseError("unexpected token to consume", c.meta());
            popBuilder();

            pb->consumeLookAhead(result);
            popBuilder();

            pushBuilder(no_lah);

            builder()->addLocal(ID("ncur"), state().cur);
            auto ms = builder::local("ms", builder::memberCall(builder::id(re), "token_matcher", {}));
            auto body = builder()->addWhile(ms, builder::bool_(true));
            pushBuilder(body);

            builder()->addLocal(ID("rc"), hilti::type::SignedInteger(32));

            builder()->addAssign(builder::tuple({builder::id("rc"), builder::id("ncur")}),
                                 builder::memberCall(builder::id("ms"), "advance", {builder::id("ncur")}), c.meta());

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

            if ( state().literal_mode != LiteralMode::Skip ) {
                if ( state().captures )
                    builder()->addAssign(*state().captures,
                                         builder::memberCall(builder::id("ms"), "captures", {state().data}));

                builder()->addAssign(*result,
                                     builder::memberCall(state().cur, "sub", {builder::begin(builder::id("ncur"))}));
            }

            pb->setInput(builder::id("ncur"));
            builder()->addBreak();
            popBuilder();

            popBuilder();

            popBuilder();

            return result;
        };

        std::optional<Expression> result;

        switch ( state().literal_mode ) {
            case LiteralMode::Default:
            case LiteralMode::Skip: {
                return parse(result);
            }

            case LiteralMode::Search: // Handled in `parseLiteral`.
            case LiteralMode::Try: {
                result = builder()->addTmp("result", state().cur);
                return parse(result);
            }
        }

        hilti::util::cannot_be_reached();
    }

    result_t operator()(const hilti::expression::Ctor& c) { return *dispatch(c.ctor()); }

    result_t parseInteger(const Type& type, const Expression& expected, const Meta& meta) {
        auto offset = [](Expression view) { return builder::memberCall(std::move(view), "offset", {}); };

        switch ( state().literal_mode ) {
            case LiteralMode::Default:
            case LiteralMode::Skip: {
                auto [have_lah, no_lah] = builder()->addIfElse(state().lahead);

                pushBuilder(have_lah);

                pushBuilder(builder()->addIf(builder::unequal(state().lahead, builder::integer(production.tokenID()))));
                pb->parseError("unexpected token to consume", meta);
                popBuilder();

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

                if ( state().literal_mode != LiteralMode::Skip )
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

        hilti::util::cannot_be_reached();
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
    if ( auto e = Visitor(this, p, dst).dispatch(p.expression()); e && *e )
        return std::move(**e);

    hilti::logger().internalError(fmt("codegen: literal parser did not return expression for '%s'", p.expression()));
}

void ParserBuilder::skipLiteral(const Production& p) {
    assert(p.isLiteral());

    auto pstate = state();
    pstate.literal_mode = LiteralMode::Skip;
    pushState(std::move(pstate));
    auto e = Visitor(this, p, {}).dispatch(p.expression());
    popState();

    if ( e )
        return;
    else
        hilti::logger().internalError(
            fmt("codegen: literal parser did not return expression for '%s'", p.expression()));
}
