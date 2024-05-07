// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <utility>

#include <hilti/ast/builder/all.h>
#include <hilti/ast/types/struct.h>
#include <hilti/base/logger.h>

#include <spicy/ast/builder/builder.h>
#include <spicy/ast/types/unit-items/field.h>
#include <spicy/ast/visitor.h>
#include <spicy/compiler/detail/codegen/codegen.h>
#include <spicy/compiler/detail/codegen/parser-builder.h>

using namespace spicy;
using namespace spicy::detail;
using namespace spicy::detail::codegen;
using hilti::util::fmt;

namespace {

struct TypeParser {
    TypeParser(ParserBuilder* pb_, const production::Meta& meta_, Expression* dst_, bool is_try_)
        : pb(pb_), meta(meta_), dst(dst_), is_try(is_try_) {}

    ParserBuilder* pb;
    const production::Meta& meta;
    Production* production = nullptr;
    Expression* dst = nullptr;
    bool is_try;

    Expression* buildParser(UnqualifiedType* t);

    auto state() { return pb->state(); }
    auto builder() { return pb->builder(); }
    auto context() { return pb->context(); }
    auto pushBuilder(std::shared_ptr<Builder> b) { return pb->pushBuilder(std::move(b)); }
    auto pushBuilder() { return pb->pushBuilder(); }
    auto pushBuilder(std::shared_ptr<Builder> b, void (*func)()) { return pb->pushBuilder(std::move(b), func); }
    auto popBuilder() { return pb->popBuilder(); }

    Expression* destination(UnqualifiedType* t) {
        if ( dst )
            return dst;

        if ( meta.field() )
            return builder()->addTmp("x", meta.field()->parseType());

        return builder()->addTmp("x", t);
    }

    Expression* performUnpack(Expression* target, UnqualifiedType* t, unsigned int len, const Expressions& unpack_args,
                              const Meta& m, bool is_try) {
        auto qt = builder()->qualifiedType(t, hilti::Constness::Mutable);

        if ( ! is_try ) {
            auto error_msg = fmt("expecting %d bytes for unpacking value", len);
            pb->waitForInput(builder()->integer(len), error_msg, m);

            auto unpacked = builder()->unpack(qt, unpack_args);
            builder()->addAssign(builder()->tuple({target, state().cur}), builder()->deref(unpacked));

            if ( ! state().needs_look_ahead )
                pb->trimInput();

            return target;
        }
        else {
            auto has_data = pb->waitForInputOrEod(builder()->integer(len));

            auto result = dst ? dst : builder()->addTmp("result", builder()->typeResult(qt));

            auto true_ = builder()->addIf(has_data);
            pushBuilder(true_);
            auto unpacked = builder()->deref(builder()->unpack(qt, unpack_args));
            builder()->addAssign(builder()->tuple({result, state().cur}), unpacked);
            popBuilder();

            // TODO(bbannier): Initialize the error state of `result` with a
            // proper message on an `else` branch.
            return result;
        }
    }

    Expression* fieldByteOrder() {
        Expression* byte_order = nullptr;

        if ( const auto& a = meta.field()->attributes()->find("&byte-order") )
            byte_order = *a->valueAsExpression();

        else if ( const auto& a = state().unit->attributes()->find("&byte-order") )
            byte_order = *a->valueAsExpression();

        else if ( const auto& p = state().unit->propertyItem("%byte-order") )
            byte_order = p->expression();

        if ( byte_order )
            return byte_order;
        else
            return builder()->id("hilti::ByteOrder::Network");
    }
};

struct Visitor : public visitor::PreOrder {
    Visitor(TypeParser* tp) : tp(tp) {}

    TypeParser* tp;
    Expression* result = nullptr;

    auto pb() { return tp->pb; }
    auto state() { return pb()->state(); }
    auto builder() { return pb()->builder(); }
    auto context() { return pb()->context(); }
    auto pushBuilder(std::shared_ptr<Builder> b) { return pb()->pushBuilder(std::move(b)); }
    auto pushBuilder() { return pb()->pushBuilder(); }
    template<typename Function>
    auto pushBuilder(std::shared_ptr<Builder> b, const Function& func) {
        return pb()->pushBuilder(std::move(b), func);
    }
    auto popBuilder() { return tp->popBuilder(); }

    void operator()(hilti::type::Address* n) final {
        auto v4 = tp->meta.field()->attributes()->find("&ipv4");
        auto v6 = tp->meta.field()->attributes()->find("&ipv6");
        (void)v6;
        assert(! (v4 && v6));

        if ( v4 )
            result = tp->performUnpack(tp->destination(n), builder()->typeAddress(), 4,
                                       {state().cur, builder()->id("hilti::AddressFamily::IPv4"), tp->fieldByteOrder()},
                                       n->meta(), tp->is_try);

        else
            result = tp->performUnpack(tp->destination(n), builder()->typeAddress(), 16,
                                       {state().cur, builder()->id("hilti::AddressFamily::IPv6"), tp->fieldByteOrder()},
                                       n->meta(), tp->is_try);
    }

    void operator()(hilti::type::Bitfield* n) final {
        Expression* bitorder = builder()->id("hilti::BitOrder::LSB0");

        if ( auto attrs = n->attributes() ) {
            if ( auto a = attrs->find("&bit-order") )
                bitorder = *a->valueAsExpression();
        }

        auto target = tp->destination(n);
        tp->performUnpack(target, n, n->width() / 8, {state().cur, tp->fieldByteOrder(), bitorder}, n->meta(),
                          tp->is_try);

        if ( pb()->options().debug ) {
            auto have_value = builder()->addIf(builder()->hasMember(target, "__value__"));
            pushBuilder(have_value, [&]() {
                // Print all the bit ranges individually so that we can include
                // their IDs, which the standard tuple output wouldn't show.
                builder()->addDebugMsg("spicy", fmt("%s = %%s", tp->meta.field()->id()),
                                       {builder()->member(target, "__value__")});

                builder()->addDebugIndent("spicy");
                for ( const auto& bits : n->bits() )
                    builder()->addDebugMsg("spicy", fmt("%s = %%s", bits->id()),
                                           {builder()->member(target, bits->id())});

                builder()->addDebugDedent("spicy");
            });
        }

        result = target;
    }

    void operator()(hilti::type::Real* n) final {
        auto type = tp->meta.field()->attributes()->find("&type");
        assert(type);
        result =
            tp->performUnpack(tp->destination(n), builder()->typeReal(), 4,
                              {state().cur, *type->valueAsExpression(), tp->fieldByteOrder()}, n->meta(), tp->is_try);
    }

    void operator()(hilti::type::SignedInteger* n) final {
        result = tp->performUnpack(tp->destination(n), builder()->typeSignedInteger(n->width()), n->width() / 8,
                                   {state().cur, tp->fieldByteOrder()}, n->meta(), tp->is_try);
    }

    void operator()(hilti::type::UnsignedInteger* n) final {
        result = tp->performUnpack(tp->destination(n), builder()->typeUnsignedInteger(n->width()), n->width() / 8,
                                   {state().cur, tp->fieldByteOrder()}, n->meta(), tp->is_try);
    }

    void operator()(hilti::type::Void* n) final { result = builder()->expressionVoid(); }

    void operator()(hilti::type::Bytes* n) final {
        auto chunked_attr = tp->meta.field()->attributes()->find("&chunked");
        auto eod_attr = tp->meta.field()->attributes()->find("&eod");
        auto size_attr = tp->meta.field()->attributes()->find("&size");
        auto until_attr = tp->meta.field()->attributes()->find("&until");
        auto until_including_attr = tp->meta.field()->attributes()->find("&until-including");

        bool to_eod = (eod_attr != nullptr); // parse to end of input data
        bool parse_attr = false;             // do we have a &parse-* attribute

        if ( (tp->meta.field()->attributes()->find("&parse-from") ||
              tp->meta.field()->attributes()->find("&parse-at")) &&
             ! (until_attr || until_including_attr) )
            parse_attr = true;

        if ( size_attr ) {
            // If we have a &size attribute, our input will have been
            // truncated accordingly. If no other attributes are set, we'll
            // parse to the end of our (limited) input data.
            if ( ! (until_attr || until_including_attr || parse_attr) )
                to_eod = true;
        }

        auto target = tp->destination(n);

        if ( to_eod || parse_attr ) {
            if ( tp->meta.field() && chunked_attr && ! tp->meta.container() )
                pb()->enableDefaultNewValueForField(false);

            if ( chunked_attr ) {
                auto loop = builder()->addWhile(builder()->bool_(true));
                pushBuilder(loop, [&]() {
                    builder()->addLocal("more_data", pb()->waitForInputOrEod(builder()->integer(1)));

                    auto have_data = builder()->addIf(builder()->size(state().cur));
                    pushBuilder(have_data, [&]() {
                        builder()->addAssign(target, state().cur);
                        pb()->advanceInput(builder()->size(state().cur));

                        const auto& field = tp->meta.field();
                        assert(field);
                        auto value = pb()->applyConvertExpression(*field, target);

                        if ( tp->meta.field() && ! tp->meta.container() )
                            pb()->newValueForField(tp->meta, value, target);
                    });

                    auto at_eod = builder()->addIf(builder()->not_(builder()->id("more_data")));
                    at_eod->addBreak();
                });
            }

            else {
                pb()->waitForEod();
                builder()->addAssign(target, state().cur);
                pb()->advanceInput(builder()->size(state().cur));
            }

            if ( eod_attr && size_attr )
                // With &eod, it's ok if we don't consume the full amount.
                // However, the code calling us won't know that, so we simply
                // pretend that we have processed it all.
                pb()->advanceInput(builder()->end(state().cur));

            result = target;
            return;
        }

        if ( until_attr || until_including_attr ) {
            Expression* until_expr = nullptr;
            if ( until_attr )
                until_expr =
                    builder()->coerceTo(*until_attr->valueAsExpression(),
                                        builder()->qualifiedType(builder()->typeBytes(), hilti::Constness::Mutable));
            else
                until_expr =
                    builder()->coerceTo(*until_including_attr->valueAsExpression(),
                                        builder()->qualifiedType(builder()->typeBytes(), hilti::Constness::Mutable));

            auto until_bytes_var = builder()->addTmp("until_bytes", until_expr);
            auto until_bytes_size_var = builder()->addTmp("until_bytes_sz", builder()->size(until_bytes_var));

            if ( tp->meta.field() && chunked_attr && ! tp->meta.container() )
                pb()->enableDefaultNewValueForField(false);

            builder()->addAssign(target, builder()->bytes(""));
            auto body = builder()->addWhile(builder()->bool_(true));
            pushBuilder(body, [&]() {
                // Helper to add a new chunk of data to the field's value,
                // behaving slightly different depending on whether we have
                // &chunked or not.
                auto add_match_data = [&](Expression* target, Expression* match) {
                    if ( chunked_attr ) {
                        builder()->addAssign(target, match);

                        if ( tp->meta.field() && ! tp->meta.container() )
                            pb()->newValueForField(tp->meta, match, target);
                    }
                    else
                        builder()->addSumAssign(target, match);
                };


                pb()->waitForInput(until_bytes_size_var,
                                   fmt("end-of-data reached before %s expression found",
                                       (until_attr ? "&until" : "&until-including")),
                                   until_expr->meta());

                auto find = builder()->memberCall(state().cur, "find", {until_bytes_var});
                auto found_id = ID("found");
                auto it_id = ID("it");
                auto found = builder()->id(found_id);
                auto it = builder()->id(it_id);
                builder()->addLocal(found_id,
                                    builder()->qualifiedType(builder()->typeBool(), hilti::Constness::Mutable));
                builder()->addLocal(it_id, builder()->qualifiedType(builder()->typeStreamIterator(),
                                                                    hilti::Constness::Mutable));
                builder()->addAssign(builder()->tuple({found, it}), find);

                Expression* match = builder()->memberCall(state().cur, "sub", {it});

                auto non_empty_match = builder()->addIf(builder()->size(match));
                pushBuilder(non_empty_match, [&]() { add_match_data(target, match); });

                auto [found_branch, not_found_branch] = builder()->addIfElse(found);

                pushBuilder(found_branch, [&]() {
                    auto new_it = builder()->sum(it, until_bytes_size_var);

                    if ( until_including_attr )
                        add_match_data(target, builder()->memberCall(state().cur, "sub", {it, new_it}));

                    pb()->advanceInput(new_it);
                    builder()->addBreak();
                });

                pushBuilder(not_found_branch, [&]() { pb()->advanceInput(it); });
            });

            result = target;
            return;
        }
    }
};

Expression* TypeParser::buildParser(UnqualifiedType* t) {
    return hilti::visitor::dispatch(Visitor(this), t, [](const auto& v) { return v.result; });
}

} // namespace

Expression* ParserBuilder::_parseType(UnqualifiedType* t, const production::Meta& meta, Expression* dst, bool is_try) {
    assert(! is_try || (t->isA<hilti::type::SignedInteger>() || t->isA<hilti::type::UnsignedInteger>() ||
                        t->isA<hilti::type::Bitfield>()));

    if ( auto e = TypeParser(this, meta, dst, is_try).buildParser(t) )
        return e;

    hilti::logger().internalError(
        fmt("codegen: type parser did not return expression for '%s' (%s)", *t, t->typename_()));
}

Expression* ParserBuilder::parseType(UnqualifiedType* t, const production::Meta& meta, Expression* dst) {
    return _parseType(t, meta, dst, /*is_try =*/false);
}

Expression* ParserBuilder::parseTypeTry(UnqualifiedType* t, const production::Meta& meta, Expression* dst) {
    assert(t->isA<hilti::type::SignedInteger>() || t->isA<hilti::type::UnsignedInteger>() ||
           t->isA<hilti::type::Bitfield>());

    return _parseType(t, meta, dst, /*is_try =*/true);
}
