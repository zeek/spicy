// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <utility>

#include <hilti/ast/builder/all.h>
#include <hilti/ast/types/struct.h>
#include <hilti/base/logger.h>

#include <spicy/ast/attribute.h>
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
    TypeParser(ParserBuilder* pb_, const production::Meta& meta_, Expression* dst_, TypesMode mode)
        : pb(pb_), meta(meta_), dst(dst_), mode(mode) {}

    ParserBuilder* pb;
    const production::Meta& meta;
    Production* production = nullptr;
    Expression* dst = nullptr;
    TypesMode mode;

    Expression* buildParser(UnqualifiedType* t);

    const auto& state() { return pb->state(); }
    auto builder() { return pb->builder(); }
    auto context() { return pb->context(); }
    auto pushBuilder(std::shared_ptr<Builder> b) { return pb->pushBuilder(std::move(b)); }
    auto pushBuilder() { return pb->pushBuilder(); }
    template<typename Func>
    auto pushBuilder(std::shared_ptr<Builder> b, Func&& func) {
        return pb->pushBuilder(std::move(b), std::forward(func));
    }
    auto popBuilder() { return pb->popBuilder(); }

    Expression* destination(UnqualifiedType* t) {
        if ( dst )
            return dst;

        if ( meta.field() && meta.isFieldProduction() )
            return builder()->addTmp("x", meta.field()->parseType());

        return builder()->addTmp("x", t);
    }

    Expression* performUnpack(Expression* target, UnqualifiedType* t, unsigned int len, const Expressions& unpack_args,
                              const Meta& m, bool is_try) {
        auto* qt = builder()->qualifiedType(t, hilti::Constness::Mutable);

        if ( ! is_try ) {
            auto error_msg = fmt("expecting %d bytes for unpacking value", len);
            pb->waitForInput(builder()->integer(len), error_msg, m);

            auto* unpacked = builder()->unpack(qt, unpack_args);
            builder()->addAssign(builder()->tuple({target, state().cur}), builder()->deref(unpacked));

            return target;
        }
        else {
            auto* has_data = pb->waitForInputOrEod(builder()->integer(len));

            auto* result = dst ? dst : builder()->addTmp("result", builder()->typeResult(qt));

            auto true_ = builder()->addIf(has_data);
            pushBuilder(std::move(true_));
            auto* unpacked = builder()->deref(builder()->unpack(qt, unpack_args));
            builder()->addAssign(builder()->tuple({result, state().cur}), unpacked);
            popBuilder();

            // TODO(bbannier): Initialize the error state of `result` with a
            // proper message on an `else` branch.
            return result;
        }
    }

    Expression* fieldByteOrder() {
        Expression* byte_order = nullptr;

        if ( const auto& a = meta.field()->attributes()->find(attribute::kind::ByteOrder) )
            byte_order = *a->valueAsExpression();

        else if ( const auto& a = state().unit->attributes()->find(attribute::kind::ByteOrder) )
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
    const auto& state() { return pb()->state(); }
    auto builder() { return pb()->builder(); }
    auto context() { return pb()->context(); }
    auto pushBuilder(std::shared_ptr<Builder> b) { return pb()->pushBuilder(std::move(b)); }
    auto pushBuilder() { return pb()->pushBuilder(); }
    template<typename Function>
    auto pushBuilder(std::shared_ptr<Builder> b, Function&& func) {
        return pb()->pushBuilder(std::move(b), func);
    }
    auto popBuilder() { return tp->popBuilder(); }

    void operator()(hilti::type::Address* n) final {
        switch ( tp->mode ) {
            case TypesMode::Default: {
                auto* v4 = tp->meta.field()->attributes()->find(attribute::kind::IPv4);
                auto* v6 = tp->meta.field()->attributes()->find(attribute::kind::IPv6);
                (void)v6;
                assert(! (v4 && v6));

                if ( v4 )
                    result = tp->performUnpack(tp->destination(n), builder()->typeAddress(), 4,
                                               {state().cur, builder()->id("hilti::AddressFamily::IPv4"),
                                                tp->fieldByteOrder()},
                                               n->meta(), tp->mode == TypesMode::Try);

                else
                    result = tp->performUnpack(tp->destination(n), builder()->typeAddress(), 16,
                                               {state().cur, builder()->id("hilti::AddressFamily::IPv6"),
                                                tp->fieldByteOrder()},
                                               n->meta(), tp->mode == TypesMode::Try);

                return;
            }

            case TypesMode::Try: hilti::logger().internalError("type cannot be used with try mode for parsing");

            case TypesMode::Optimize: {
                return; // not supported
            }
        }

        hilti::rt::cannot_be_reached();
    }

    void operator()(hilti::type::Bitfield* n) final {
        switch ( tp->mode ) {
            case TypesMode::Default:
            case TypesMode::Try: {
                Expression* bitorder = builder()->id("hilti::BitOrder::LSB0");

                if ( auto* attrs = n->attributes() ) {
                    if ( auto* a = attrs->find(attribute::kind::BitOrder) )
                        bitorder = *a->valueAsExpression();
                }

                auto* target = tp->destination(n);
                tp->performUnpack(target, n, n->width() / 8, {state().cur, tp->fieldByteOrder(), bitorder}, n->meta(),
                                  tp->mode == TypesMode::Try);

                if ( pb()->options().debug ) {
                    auto have_value = builder()->addIf(builder()->hasMember(target, HILTI_INTERNAL_ID("value")));
                    pushBuilder(std::move(have_value), [&]() {
                        // Print all the bit ranges individually so that we can include
                        // their IDs, which the standard tuple output wouldn't show.
                        builder()->addDebugMsg("spicy", fmt("%s = %%s", tp->meta.field()->id()),
                                               {builder()->member(target, HILTI_INTERNAL_ID("value"))});

                        builder()->addDebugIndent("spicy");
                        for ( const auto& bits : n->bits() )
                            builder()->addDebugMsg("spicy", fmt("%s = %%s", bits->id()),
                                                   {builder()->member(target, bits->id())});

                        builder()->addDebugDedent("spicy");
                    });
                }

                result = target;
                return;
            }

            case TypesMode::Optimize: {
                return; // not supported
            }
        }

        hilti::rt::cannot_be_reached();
    }

    void operator()(hilti::type::Real* n) final {
        switch ( tp->mode ) {
            case TypesMode::Default: {
                auto* type = tp->meta.field()->attributes()->find(attribute::kind::Type);
                assert(type);
                result = tp->performUnpack(tp->destination(n), builder()->typeReal(), 4,
                                           {state().cur, *type->valueAsExpression(), tp->fieldByteOrder()}, n->meta(),
                                           false);
                return;
            }

            case TypesMode::Try: hilti::logger().internalError("type cannot be used with try mode for parsing");

            case TypesMode::Optimize: {
                return; // not supported
            }
        }

        hilti::rt::cannot_be_reached();
    }

    void operator()(hilti::type::SignedInteger* n) final {
        switch ( tp->mode ) {
            case TypesMode::Default:
            case TypesMode::Try: {
                result = tp->performUnpack(tp->destination(n), builder()->typeSignedInteger(n->width()), n->width() / 8,
                                           {state().cur, tp->fieldByteOrder()}, n->meta(), tp->mode == TypesMode::Try);
                return;
            }

            case TypesMode::Optimize: {
                return; // not supported
            }
        }

        hilti::rt::cannot_be_reached();
    }

    void operator()(hilti::type::UnsignedInteger* n) final {
        switch ( tp->mode ) {
            case TypesMode::Default:
            case TypesMode::Try: {
                result =
                    tp->performUnpack(tp->destination(n), builder()->typeUnsignedInteger(n->width()), n->width() / 8,
                                      {state().cur, tp->fieldByteOrder()}, n->meta(), tp->mode == TypesMode::Try);
                return;
            }

            case TypesMode::Optimize: {
                return; // not supported
            }
        }

        hilti::rt::cannot_be_reached();
    }

    void operator()(hilti::type::Void* n) final {
        switch ( tp->mode ) {
            case TypesMode::Default: {
                result = builder()->expressionVoid();
                return;
            }

            case TypesMode::Try: hilti::logger().internalError("type cannot be used with try mode for parsing");

            case TypesMode::Optimize: {
                return; // not supported
            }
        }

        hilti::rt::cannot_be_reached();
    }

    void operator()(hilti::type::Bytes* n) final {
        auto* attrs = tp->meta.field()->attributes();
        auto* chunked_attr = attrs->find(attribute::kind::Chunked);
        auto* eod_attr = attrs->find(attribute::kind::Eod);
        auto* size_attr = attrs->find(attribute::kind::Size);
        auto* until_attr = attrs->find(attribute::kind::Until);
        auto* until_including_attr = attrs->find(attribute::kind::UntilIncluding);

        bool to_eod = (eod_attr != nullptr); // parse to end of input data
        bool parse_attr = false;             // do we have a &parse-* attribute

        if ( (tp->meta.field()->attributes()->find(attribute::kind::ParseFrom) ||
              tp->meta.field()->attributes()->find(attribute::kind::ParseAt)) &&
             ! (until_attr || until_including_attr) )
            parse_attr = true;

        if ( size_attr ) {
            // If we have a &size attribute, our input will have been
            // truncated accordingly. If no other attributes are set, we'll
            // parse to the end of our (limited) input data.
            if ( ! (until_attr || until_including_attr || parse_attr) )
                to_eod = true;
        }

        auto* target = tp->destination(n);

        switch ( tp->mode ) {
            case TypesMode::Default: {
                if ( to_eod || parse_attr ) {
                    if ( tp->meta.field() && chunked_attr && ! tp->meta.container() )
                        pb()->enableDefaultNewValueForField(false);

                    if ( chunked_attr ) {
                        auto loop = builder()->addWhile(builder()->bool_(true));
                        pushBuilder(std::move(loop), [&]() {
                            builder()->addLocal("more_data", pb()->waitForInputOrEod(builder()->integer(1)));

                            auto have_data = builder()->addIf(builder()->size(state().cur));
                            pushBuilder(std::move(have_data), [&]() {
                                builder()->addAssign(target, state().cur);
                                pb()->advanceInput(builder()->size(state().cur));

                                const auto& field = tp->meta.field();
                                assert(field);
                                auto* value = pb()->applyConvertExpression(*field, target);

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
                        until_expr = builder()->coerceTo(*until_attr->valueAsExpression(),
                                                         builder()->qualifiedType(builder()->typeBytes(),
                                                                                  hilti::Constness::Mutable));
                    else
                        until_expr = builder()->coerceTo(*until_including_attr->valueAsExpression(),
                                                         builder()->qualifiedType(builder()->typeBytes(),
                                                                                  hilti::Constness::Mutable));

                    auto* until_bytes_var = builder()->addTmp("until_bytes", until_expr);
                    auto* until_bytes_size_var = builder()->addTmp("until_bytes_sz", builder()->size(until_bytes_var));

                    if ( tp->meta.field() && chunked_attr && ! tp->meta.container() )
                        pb()->enableDefaultNewValueForField(false);

                    builder()->addAssign(target, builder()->bytes(""));
                    auto body = builder()->addWhile(builder()->bool_(true));
                    pushBuilder(std::move(body), [&]() {
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

                        auto* find = builder()->memberCall(state().cur, "find", {until_bytes_var});
                        auto found_id = ID("found");
                        auto it_id = ID("it");
                        auto* found = builder()->id(found_id);
                        auto* it = builder()->id(it_id);
                        builder()->addLocal(std::move(found_id),
                                            builder()->qualifiedType(builder()->typeBool(), hilti::Constness::Mutable));
                        builder()->addLocal(std::move(it_id), builder()->qualifiedType(builder()->typeStreamIterator(),
                                                                                       hilti::Constness::Mutable));
                        builder()->addAssign(builder()->tuple({found, it}), find);

                        Expression* match = builder()->memberCall(state().cur, "sub", {it});

                        auto non_empty_match = builder()->addIf(builder()->size(match));
                        pushBuilder(std::move(non_empty_match), [&]() { add_match_data(target, match); });

                        auto [found_branch, not_found_branch] = builder()->addIfElse(found);

                        pushBuilder(std::move(found_branch), [&]() {
                            auto* new_it = builder()->sum(it, until_bytes_size_var);

                            if ( until_including_attr )
                                add_match_data(target, builder()->memberCall(state().cur, "sub", {it, new_it}));

                            pb()->advanceInput(new_it);
                            builder()->addBreak();
                        });

                        pushBuilder(std::move(not_found_branch), [&]() { pb()->advanceInput(it); });
                    });

                    result = target;
                    return;
                }

                hilti::rt::cannot_be_reached();
            }

            case TypesMode::Try: hilti::logger().internalError("type cannot be used with try mode for parsing");

            case TypesMode::Optimize: {
                auto parse_attrs = ParserBuilder::removeGenericParseAttributes(attrs);
                if ( size_attr && parse_attrs.size() == 0 ) {
                    auto* length = pb()->evaluateAttributeExpression(size_attr, "size");
                    auto* eod_ok = builder()->bool_(eod_attr ? true : false);
                    auto* value =
                        builder()->call("spicy_rt::extractBytes", {state().data, state().cur, length, eod_ok,
                                                                   builder()->expression(tp->meta.field()->meta()),
                                                                   pb()->currentFilters(state())});
                    builder()->addAssign(target, value);
                    pb()->advanceInput(length);
                    result = target;
                    return;
                }

                return; // not supported
            }
        }

        hilti::rt::cannot_be_reached();
    }
};

Expression* TypeParser::buildParser(UnqualifiedType* t) {
    return hilti::visitor::dispatch(Visitor(this), t, [](const auto& v) { return v.result; });
}

} // namespace

Expression* ParserBuilder::parseType(UnqualifiedType* t, const production::Meta& meta, Expression* dst, TypesMode mode,
                                     bool no_trim) {
    if ( auto* e = TypeParser(this, meta, dst, mode).buildParser(t); e || mode == TypesMode::Optimize ) {
        if ( mode == TypesMode::Default && ! no_trim )
            trimInput();

        return e;
    }

    hilti::logger().internalError(
        fmt("codegen: type parser did not return expression for '%s' (%s)", *t, t->typename_()));
}
