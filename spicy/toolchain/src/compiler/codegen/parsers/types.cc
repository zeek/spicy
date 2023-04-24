// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <utility>

#include <hilti/ast/builder/all.h>
#include <hilti/ast/builder/expression.h>
#include <hilti/ast/types/struct.h>
#include <hilti/base/logger.h>

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
    Visitor(ParserBuilder* pb_, const production::Meta& meta_, const std::optional<Expression>& dst_, bool is_try_)
        : pb(pb_), meta(meta_), dst(dst_), is_try(is_try_) {}
    ParserBuilder* pb;
    const production::Meta& meta;
    const std::optional<Expression>& dst;
    bool is_try;

    auto state() { return pb->state(); }
    auto builder() { return pb->builder(); }
    auto pushBuilder(std::shared_ptr<builder::Builder> b) { return pb->pushBuilder(std::move(b)); }
    auto pushBuilder(std::shared_ptr<builder::Builder> b, const std::function<void()>& f) {
        return pb->pushBuilder(std::move(b), f);
    }
    auto pushBuilder() { return pb->pushBuilder(); }
    auto popBuilder() { return pb->popBuilder(); }
    auto guardBuilder() { return pb->makeScopeGuard(); }

    Expression destination(const Type& t) {
        if ( dst )
            return *dst;

        if ( meta.field() )
            return builder()->addTmp("x", meta.field()->parseType());

        return builder()->addTmp("x", t);
    }

    Expression performUnpack(const Expression& target, const Type& t, int len, const std::vector<Expression>& unpack_args,
                             const Meta& m, bool is_try) {
        if ( ! is_try ) {
            auto error_msg = fmt("expecting %d bytes for unpacking value", len);
            pb->waitForInput(builder::integer(len), error_msg, m);

            auto unpacked = builder::unpack(t, unpack_args);
            builder()->addAssign(builder::tuple({target, state().cur}), builder::deref(unpacked));

            if ( ! state().needs_look_ahead )
                pb->trimInput();

            return target;
        }
        else {
            auto has_data = pb->waitForInputOrEod(builder::integer(len));

            auto result = builder()->addTmp("result", type::Result(t));

            auto true_ = builder()->addIf(has_data);
            pushBuilder(true_);
            auto unpacked = builder::deref(builder::unpack(t, unpack_args));
            builder()->addAssign(builder::tuple({result, state().cur}), unpacked);
            popBuilder();

            // TODO(bbannier): Initialize the error state of `result` with a
            // proper message on an `else` branch.
            return result;
        }
    }

    Expression fieldByteOrder() {
        std::optional<Expression> byte_order;

        if ( const auto& a = AttributeSet::find(meta.field()->attributes(), "&byte-order") )
            byte_order = *a->valueAsExpression();

        else if ( const auto& a = AttributeSet::find(state().unit.get().attributes(), "&byte-order") )
            byte_order = *a->valueAsExpression();

        else if ( const auto& p = state().unit.get().propertyItem("%byte-order") )
            byte_order = *p->expression();

        if ( byte_order )
            return std::move(*byte_order);
        else
            return builder::id("hilti::ByteOrder::Network");
    }

    result_t operator()(const hilti::type::Address& t) {
        auto v4 = AttributeSet::find(meta.field()->attributes(), "&ipv4");
        auto v6 = AttributeSet::find(meta.field()->attributes(), "&ipv6");
        (void)v6;
        assert(! (v4 && v6));

        if ( v4 )
            return performUnpack(destination(t), type::Address(), 4,
                                 {state().cur, builder::id("hilti::AddressFamily::IPv4"), fieldByteOrder()}, t.meta(),
                                 is_try);

        else
            return performUnpack(destination(t), type::Address(), 16,
                                 {state().cur, builder::id("hilti::AddressFamily::IPv6"), fieldByteOrder()}, t.meta(),
                                 is_try);
    }

    result_t operator()(const spicy::type::Bitfield& t) {
        const auto& itype = t.parseType();
        auto value = builder()->addTmp("bitfield", itype);
        performUnpack(value, itype, t.width() / 8, {state().cur, fieldByteOrder()}, t.meta(), is_try);

        builder()->addDebugMsg("spicy", fmt("%s = %%s", meta.field()->id()), {value});
        builder()->addDebugIndent("spicy");

        std::vector<Expression> extracted_bits;

        for ( const auto& b : t.bits() ) {
            auto bit_order = builder::id("spicy_rt::BitOrder::LSB0");

            if ( const auto& a = AttributeSet::find(meta.field()->attributes(), "&bit-order") )
                bit_order = *a->valueAsExpression();
            else if ( const auto& p = state().unit.get().propertyItem("%bit-order") )
                bit_order = *p->expression();

            auto x =
                builder()->addTmp("bits", itype,
                                  builder::call("spicy_rt::extractBits", {value, builder::integer(b.lower()),
                                                                          builder::integer(b.upper()), bit_order}));

            if ( auto a = AttributeSet::find(b.attributes(), "&convert") ) {
                auto converted = builder()->addTmp(ID("converted"), b.itemType());
                auto block = builder()->addBlock();
                block->addLocal(ID("__dd"), itype, x);
                block->addAssign(converted, *a->valueAsExpression());
                x = converted;
            }

            extracted_bits.push_back(x);
            builder()->addDebugMsg("spicy", fmt("%s = %%s", b.id()), {x});
        }

        builder()->addDebugDedent("spicy");

        auto target = destination(t.type());
        builder()->addAssign(target, builder::tuple(extracted_bits));
        return target;
    }

    result_t operator()(const hilti::type::Real& t) {
        auto type = AttributeSet::find(meta.field()->attributes(), "&type");
        assert(type);
        return performUnpack(destination(t), type::Real(), 4,
                             {state().cur, *type->valueAsExpression(), fieldByteOrder()}, t.meta(), is_try);
    }

    result_t operator()(const hilti::type::SignedInteger& t) {
        return performUnpack(destination(t), t, t.width() / 8, {state().cur, fieldByteOrder()}, t.meta(), is_try);
    }

    result_t operator()(const hilti::type::UnsignedInteger& t) {
        return performUnpack(destination(t), t, t.width() / 8, {state().cur, fieldByteOrder()}, t.meta(), is_try);
    }

    result_t operator()(const hilti::type::Void& t) {
        return hilti::expression::Void();
    }

    result_t operator()(const hilti::type::Bytes& t) {
        auto chunked_attr = AttributeSet::find(meta.field()->attributes(), "&chunked");
        auto eod_attr = AttributeSet::find(meta.field()->attributes(), "&eod");
        auto size_attr = AttributeSet::find(meta.field()->attributes(), "&size");
        auto until_attr = AttributeSet::find(meta.field()->attributes(), "&until");
        auto until_including_attr = AttributeSet::find(meta.field()->attributes(), "&until-including");

        bool to_eod = eod_attr.has_value(); // parse to end of input data
        bool parse_attr = false;            // do we have a &parse-* attribute

        if ( (AttributeSet::find(meta.field()->attributes(), "&parse-from") ||
              AttributeSet::find(meta.field()->attributes(), "&parse-at")) &&
             ! (until_attr || until_including_attr) )
            parse_attr = true;

        if ( size_attr ) {
            // If we have a &size attribute, our input will have been
            // truncated accordingly. If no other attributes are set, we'll
            // parse to the end of our (limited) input data.
            if ( ! (until_attr || until_including_attr || parse_attr) )
                to_eod = true;
        }

        auto target = destination(t);

        if ( to_eod || parse_attr ) {
            if ( meta.field() && chunked_attr && ! meta.container() )
                pb->enableDefaultNewValueForField(false);

            if ( chunked_attr ) {
                auto loop = builder()->addWhile(builder::bool_(true));
                pushBuilder(loop, [&]() {
                    builder()->addLocal("more_data", pb->waitForInputOrEod(builder::integer(1)));

                    auto have_data = builder()->addIf(builder::size(state().cur));
                    pushBuilder(have_data, [&]() {
                        builder()->addAssign(target, state().cur);
                        pb->advanceInput(builder::size(state().cur));

                        const auto& field = meta.field();
                        assert(field);
                        auto value = pb->applyConvertExpression(*field, target);

                        if ( meta.field() && ! meta.container() )
                            pb->newValueForField(meta, value, target);
                    });

                    auto at_eod = builder()->addIf(builder::not_(builder::id("more_data")));
                    at_eod->addBreak();
                });
            }

            else {
                pb->waitForEod();
                builder()->addAssign(target, state().cur);
                pb->advanceInput(builder::size(state().cur));
            }

            if ( eod_attr && size_attr )
                // With &eod, it's ok if we don't consume the full amount.
                // However, the code calling us won't know that, so we simply
                // pretend that we have processed it all.
                pb->advanceInput(builder::end(state().cur));

            return target;
        }

        if ( until_attr || until_including_attr ) {
            Expression until_expr;
            if ( until_attr )
                until_expr = builder::coerceTo(*until_attr->valueAsExpression(), hilti::type::Bytes());
            else
                until_expr = builder::coerceTo(*until_including_attr->valueAsExpression(), hilti::type::Bytes());

            auto until_bytes_var = builder()->addTmp("until_bytes", until_expr);
            auto until_bytes_size_var = builder()->addTmp("until_bytes_sz", builder::size(until_bytes_var));

            if ( meta.field() && chunked_attr && ! meta.container() )
                pb->enableDefaultNewValueForField(false);

            builder()->addAssign(target, builder::bytes(""));
            auto body = builder()->addWhile(builder::bool_(true));
            pushBuilder(body, [&]() {
                // Helper to add a new chunk of data to the field's value,
                // behaving slightly different depending on whether we have
                // &chunked or not.
                auto add_match_data = [&](const Expression& target, const Expression& match) {
                    if ( chunked_attr ) {
                        builder()->addAssign(target, match);

                        if ( meta.field() && ! meta.container() )
                            pb->newValueForField(meta, match, target);
                    }
                    else
                        builder()->addSumAssign(target, match);
                };


                pb->waitForInput(until_bytes_size_var,
                                 fmt("end-of-data reached before %s expression found",
                                     (until_attr ? "&until" : "&until-including")),
                                 until_expr.meta());

                auto find = builder::memberCall(state().cur, "find", {until_bytes_var});
                auto found_id = ID("found");
                auto it_id = ID("it");
                auto found = builder::id(found_id);
                auto it = builder::id(it_id);
                builder()->addLocal(found_id, type::Bool());
                builder()->addLocal(it_id, type::stream::Iterator());
                builder()->addAssign(builder::tuple({found, it}), find);

                Expression match = builder::memberCall(state().cur, "sub", {it});

                auto non_empty_match = builder()->addIf(builder::size(match));
                pushBuilder(non_empty_match, [&]() { add_match_data(target, match); });

                auto [found_branch, not_found_branch] = builder()->addIfElse(found);

                pushBuilder(found_branch, [&]() {
                    auto new_it = builder::sum(it, until_bytes_size_var);

                    if ( until_including_attr )
                        add_match_data(target, builder::memberCall(state().cur, "sub", {it, new_it}));

                    pb->advanceInput(new_it);
                    builder()->addBreak();
                });

                pushBuilder(not_found_branch, [&]() { pb->advanceInput(it); });
            });

            return target;
        }

        return {};
    }
};

} // namespace

Expression ParserBuilder::_parseType(const Type& t, const production::Meta& meta, const std::optional<Expression>& dst,
                                     bool is_try) {
    assert(! is_try || (t.isA<type::SignedInteger>() || t.isA<type::UnsignedInteger>()));

    if ( auto e = Visitor(this, meta, dst, is_try).dispatch(t) )
        return std::move(*e);

    hilti::logger().internalError(fmt("codegen: type parser did not return expression for '%s'", t));
}

Expression ParserBuilder::parseType(const Type& t, const production::Meta& meta, const std::optional<Expression>& dst) {
    return _parseType(t, meta, dst, /*is_try =*/false);
}

Expression ParserBuilder::parseTypeTry(const Type& t, const production::Meta& meta,
                                       const std::optional<Expression>& dst) {
    assert(t.isA<type::SignedInteger>() || t.isA<type::UnsignedInteger>());

    return _parseType(t, meta, dst, /*is_try =*/true);
}
