// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/builder/all.h>
#include <hilti/ast/types/struct.h>
#include <hilti/base/logger.h>
#include <spicy/ast/detail/visitor.h>
#include <spicy/ast/types/unit-items/field.h>
#include <spicy/compiler/detail/codegen/codegen.h>
#include <spicy/compiler/detail/codegen/parser-builder.h>

#include <utility>

using namespace spicy;
using namespace spicy::detail;
using namespace spicy::detail::codegen;
using util::fmt;

namespace builder = hilti::builder;

namespace {

struct Visitor : public hilti::visitor::PreOrder<Expression, Visitor> {
    Visitor(ParserBuilder* pb_, const std::optional<type::unit::item::Field>& field_,
            const std::optional<Expression>& dst_, bool is_try_)
        : pb(pb_), field(field_), dst(dst_), is_try(is_try_) {}
    ParserBuilder* pb;
    const std::optional<type::unit::item::Field>& field;
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

        if ( field )
            return builder()->addTmp("x", field->parseType());

        return builder()->addTmp("x", t);
    }

    Expression performUnpack(const Expression& target, const Type& t, int len, std::vector<Expression> unpack_args,
                             const Meta& m, bool is_try) {
        if ( ! is_try ) {
            auto error_msg = fmt("expecting %d bytes for unpacking value", len);
            pb->waitForInput(builder::integer(len), error_msg, m);

            auto unpacked = builder::unpack(t, std::move(unpack_args));
            builder()->addAssign(builder::tuple({target, state().cur}), builder::deref(unpacked));
            pb->trimInput();
            return target;
        }
        else {
            auto has_data = pb->waitForInputOrEod(builder::integer(len));

            auto result = builder()->addTmp("result", type::Result(t));

            auto true_ = builder()->addIf(has_data);
            pushBuilder(true_);
            auto unpacked = builder::deref(builder::unpack(t, std::move(unpack_args)));
            builder()->addAssign(builder::tuple({result, state().cur}), unpacked);
            popBuilder();

            // TODO(bbannier): Initialize the error state of `result` with a
            // proper message on an `else` branch.
            return result;
        }
    }

    Expression fieldByteOrder() {
        std::optional<Expression> byte_order;

        if ( const auto& a = AttributeSet::find(field->attributes(), "&byte-order") )
            byte_order = *a->valueAs<spicy::Expression>();
        else if ( const auto& p = state().unit.get().propertyItem("%byte-order") )
            byte_order = *p->expression();


        if ( byte_order )
            return builder::expect_type(std::move(*byte_order), builder::typeByID("spicy::ByteOrder"));
        else
            return builder::id("hilti::ByteOrder::Network");
    }

    result_t operator()(const hilti::type::Address& t) {
        auto v4 = AttributeSet::find(field->attributes(), "&ipv4");
        auto v6 = AttributeSet::find(field->attributes(), "&ipv6");
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
        auto itype = hilti::type::UnsignedInteger(t.width(), t.meta());
        auto value = builder()->addTmp("bitfield", itype);
        performUnpack(value, itype, t.width() / 8, {state().cur, fieldByteOrder()}, t.meta(), is_try);

        builder()->addDebugMsg("spicy", fmt("%s = %%s", field->id()), {value});
        builder()->addDebugIndent("spicy");

        std::vector<Expression> extracted_bits;

        for ( const auto& b : t.bits() ) {
            auto bit_order = builder::id("spicy_rt::BitOrder::LSB0");

            if ( const auto& a = AttributeSet::find(field->attributes(), "&bit-order") )
                bit_order = *a->valueAs<spicy::Expression>();
            else if ( const auto& p = state().unit.get().propertyItem("%bit-order") )
                bit_order = *p->expression();

            auto x =
                builder()->addTmp("bits", itype,
                                  builder::call("spicy_rt::extractBits", {value, builder::integer(b.lower()),
                                                                          builder::integer(b.upper()), bit_order}));

            if ( auto a = AttributeSet::find(b.attributes(), "&convert") ) {
                auto converted = builder()->addTmp(ID("converted"), b.type());
                auto block = builder()->addBlock();
                block->addLocal(ID("__dd"), itype, x);
                block->addAssign(converted, *a->valueAs<Expression>());
                x = converted;
            }

            extracted_bits.push_back(x);
            builder()->addDebugMsg("spicy", fmt("%s = %%s", b.id()), {x});
        }

        builder()->addDebugDedent("spicy");

        auto target = destination(t.type());
        builder()->addAssign(target, builder::tuple(std::move(extracted_bits)));
        return target;
    }

    result_t operator()(const hilti::type::Real& t) {
        auto type = AttributeSet::find(field->attributes(), "&type");
        assert(type);
        return performUnpack(destination(t), type::Real(), 4,
                             {state().cur, *type->valueAs<Expression>(), fieldByteOrder()}, t.meta(), is_try);
    }

    result_t operator()(const hilti::type::SignedInteger& t) {
        return performUnpack(destination(t), t, t.width() / 8, {state().cur, fieldByteOrder()}, t.meta(), is_try);
    }

    result_t operator()(const hilti::type::UnsignedInteger& t) {
        return performUnpack(destination(t), t, t.width() / 8, {state().cur, fieldByteOrder()}, t.meta(), is_try);
    }

    result_t operator()(const hilti::type::Void& /* t */) { return hilti::expression::Void(); }

    result_t operator()(const hilti::type::Bytes& t) {
        auto eod_attr = AttributeSet::find(field->attributes(), "&eod");
        auto size_attr = AttributeSet::find(field->attributes(), "&size");
        auto until_attr = AttributeSet::find(field->attributes(), "&until");
        auto chunked_attr = AttributeSet::find(field->attributes(), "&chunked");
        bool parse_attr = false;

        if ( (AttributeSet::find(field->attributes(), "&parse-from") ||
              AttributeSet::find(field->attributes(), "&parse-at")) &&
             ! (size_attr || until_attr) )
            parse_attr = true;

        auto target = destination(t);

        if ( eod_attr || parse_attr || size_attr ) {
            pb->enableDefaultNewValueForField(false);

            auto new_data = [&]() {
                auto have_data = builder()->addIf(builder::size(state().cur));
                pushBuilder(have_data, [&]() {
                    builder()->addAssign(target, state().cur);
                    pb->advanceInput(builder::size(state().cur));

                    if ( field )
                        pb->newValueForField(*field, target);
                });
            };

            auto check_size = [&](const auto& have) {
                auto want = builder::coerceTo(*size_attr->valueAs<Expression>(), type::UnsignedInteger(64));
                auto insufficient = builder()->addIf(builder::unequal(have, want));
                pushBuilder(insufficient);
                pb->parseError("insufficient input for &size", size_attr->meta());
                popBuilder();
            };

            if ( chunked_attr ) {
                std::optional<Expression> orig_begin;

                if ( size_attr && ! eod_attr )
                    orig_begin = builder()->addTmp("orig_begin", builder::begin(state().cur));

                auto loop = builder()->addWhile(builder::bool_(true));
                pushBuilder(loop, [&]() {
                    builder()->addLocal("more_data", pb->waitForInputOrEod(builder::integer(1)));
                    new_data();
                    auto at_eod = builder()->addIf(builder::not_(builder::id("more_data")));

                    pushBuilder(at_eod);

                    if ( orig_begin )
                        check_size(builder::difference(builder::begin(state().cur), *orig_begin));

                    builder()->addBreak();

                    popBuilder();
                });
            }

            else {
                pb->waitForEod();

                if ( size_attr && ! eod_attr )
                    check_size(builder::size(state().cur));

                new_data();
            }

            return target;
        }

        if ( until_attr ) {
            auto until_expr = builder::coerceTo(*until_attr->valueAs<Expression>(), hilti::type::Bytes());
            auto until_bytes_var = builder()->addTmp("until_bytes", until_expr);
            auto until_bytes_size_var = builder()->addTmp("until_bytes_sz", builder::size(until_bytes_var));

            builder()->addAssign(target, builder::bytes(""));
            auto body = builder()->addWhile(builder::bool_(true));
            pushBuilder(body, [&]() {
                pb->waitForInput(until_bytes_size_var, "end-of-data reached before &until expression found", t.meta());

                auto find = builder::memberCall(state().cur, "find", {until_bytes_var});
                auto found_id = ID("found");
                auto it_id = ID("it");
                auto found = builder::id(found_id);
                auto it = builder::id(it_id);
                builder()->addLocal(found_id, type::Bool());
                builder()->addLocal(it_id, type::stream::Iterator());
                builder()->addAssign(builder::tuple({found, it}), find);
                builder()->addSumAssign(target, builder::memberCall(state().cur, "sub", {it}));

                auto [found_branch, not_found_branch] = builder()->addIfElse(found);

                pushBuilder(found_branch, [&]() {
                    pb->advanceInput(builder::sum(it, until_bytes_size_var));
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

Expression ParserBuilder::_parseType(const Type& t, const std::optional<type::unit::item::Field>& field,
                                     const std::optional<Expression>& dst, bool is_try) {
    assert(! is_try || (t.isA<type::SignedInteger>() || t.isA<type::UnsignedInteger>()));

    if ( auto e = Visitor(this, field, dst, is_try).dispatch(t) )
        return std::move(*e);

    hilti::logger().internalError(fmt("codegen: type parser did not return expression for '%s'", t));
}

Expression ParserBuilder::parseType(const Type& t, const std::optional<type::unit::item::Field>& field,
                                    const std::optional<Expression>& dst) {
    return _parseType(t, field, dst, /*is_try =*/false);
}

Expression ParserBuilder::parseTypeTry(const Type& t, const std::optional<type::unit::item::Field>& field,
                                       const std::optional<Expression>& dst) {
    assert(t.isA<type::SignedInteger>() || t.isA<type::UnsignedInteger>());

    return _parseType(t, field, dst, /*is_try =*/true);
}
