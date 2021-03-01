// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#include <utility>

#include <hilti/ast/builder/all.h>
#include <hilti/ast/ctors/regexp.h>
#include <hilti/ast/declarations/local-variable.h>
#include <hilti/ast/expressions/ctor.h>
#include <hilti/ast/expressions/id.h>
#include <hilti/ast/expressions/type-wrapped.h>
#include <hilti/ast/expressions/void.h>
#include <hilti/ast/statements/declaration.h>
#include <hilti/ast/types/integer.h>
#include <hilti/ast/types/stream.h>
#include <hilti/ast/types/struct.h>
#include <hilti/base/cache.h>
#include <hilti/base/logger.h>
#include <hilti/compiler/context.h>

#include <spicy/ast/types/bitfield.h>
#include <spicy/ast/types/unit-items/field.h>
#include <spicy/ast/types/unit-items/sink.h>
#include <spicy/compiler/detail/codegen/codegen.h>
#include <spicy/compiler/detail/codegen/grammar.h>
#include <spicy/compiler/detail/codegen/parser-builder.h>
#include <spicy/compiler/detail/codegen/production.h>
#include <spicy/compiler/detail/codegen/productions/all.h>

// Enable visitor usage for Production. Order of includes is important here.
#include <spicy/autogen/__dispatchers-productions.h>

#include <hilti/base/visitor.h>

using namespace spicy;
using namespace spicy::detail;
using namespace spicy::detail::codegen;
using hilti::util::fmt;

namespace builder = hilti::builder;

namespace spicy::logging::debug {
inline const hilti::logging::DebugStream ParserBuilder("parser-builder");
} // namespace spicy::logging::debug

const hilti::Type look_ahead::Type = hilti::type::SignedInteger(64); // TODO(cppcoreguidelines-interfaces-global-init)
const hilti::Expression look_ahead::None = builder::integer(0);      // TODO(cppcoreguidelines-interfaces-global-init)
const hilti::Expression look_ahead::Eod = builder::integer(-1);      // TODO(cppcoreguidelines-interfaces-global-init)

ParserState::ParserState(const type::Unit& unit, const Grammar& grammar, Expression data, Expression cur)
    : unit(std::cref(unit)),
      unit_id(*unit.typeID()),
      needs_look_ahead(grammar.needsLookAhead()),
      self(hilti::expression::UnresolvedID(ID("self"))),
      data(std::move(data)),
      cur(std::move(cur)) {}

void ParserState::printDebug(const std::shared_ptr<builder::Builder>& builder) const {
    builder->addCall("spicy_rt::printParserState", {builder::string(unit_id), data, cur, lahead, lahead_end,
                                                    builder::string(to_string(literal_mode)), trim});
}

namespace spicy::detail::codegen {

struct ProductionVisitor
    : public hilti::detail::visitor::Visitor<void, ProductionVisitor, Production, hilti::detail::visitor::Order::Pre> {
    ProductionVisitor(ParserBuilder* pb, const Grammar& g) : pb(pb), grammar(g) {}
    auto cg() { return pb->cg(); }
    auto state() { return pb->state(); }
    void pushState(ParserState p) { pb->pushState(std::move(p)); }
    auto popState() { return pb->popState(); }

    auto builder() { return pb->builder(); }
    auto pushBuilder(std::shared_ptr<builder::Builder> b) { return pb->pushBuilder(std::move(b)); }
    auto pushBuilder() { return pb->pushBuilder(); }
    auto pushBuilder(std::shared_ptr<hilti::builder::Builder> b, const std::function<void()>& func) {
        return pb->pushBuilder(std::move(b), func);
    }
    auto popBuilder() { return pb->popBuilder(); }

    auto destination() { return _destinations.back(); }

    auto pushDestination(Expression e) {
        HILTI_DEBUG(spicy::logging::debug::ParserBuilder, fmt("- push destination: %s", e));
        _destinations.emplace_back(std::move(e));
    }

    auto popDestination() {
        auto back = _destinations.back();
        _destinations.pop_back();

        if ( _destinations.size() ) {
            HILTI_DEBUG(spicy::logging::debug::ParserBuilder, fmt("- pop destination, now: %s", destination()));
        }
        else
            HILTI_DEBUG(spicy::logging::debug::ParserBuilder, fmt("- pop destination, now: none"));

        return back;
    }

    ParserBuilder* pb;
    const Grammar& grammar;
    hilti::util::Cache<std::string, ID> parse_functions;
    std::vector<hilti::type::struct_::Field> new_fields;
    std::vector<Expression> _destinations;

    void beginProduction(const Production& p) {
        HILTI_DEBUG(spicy::logging::debug::ParserBuilder, fmt("- begin production"));

        builder()->addComment(fmt("Begin parsing production: %s", hilti::util::trim(std::string(p))),
                              hilti::statement::comment::Separator::Before);
        if ( pb->options().debug ) {
            pb->state().printDebug(builder());
            builder()->addDebugMsg("spicy-verbose", fmt("- parsing production: %s", hilti::util::trim(std::string(p))));
            builder()->addCall("hilti::debugIndent", {builder::string("spicy-verbose")});
        }

        pb->saveParsePosition();
    }

    void endProduction(const Production& p) {
        HILTI_DEBUG(spicy::logging::debug::ParserBuilder, fmt("- end production"));

        if ( pb->options().debug )
            builder()->addCall("hilti::debugDedent", {builder::string("spicy-verbose")});

        builder()->addComment(fmt("End parsing production: %s", hilti::util::trim(std::string(p))),
                              hilti::statement::comment::Separator::After);
    }

    void parseNonAtomicProduction(const Production& p, const std::optional<type::Unit>& unit) {
        // We wrap the parsing of a non-atomic production into a new
        // function that's cached and reused. This ensures correct
        // operation for productions that recurse.
        auto id = parse_functions.getOrCreate(
            p.symbol(), [&]() { return unit ? ID("__parse_stage1") : ID(fmt("__parse_%s_stage1", p.symbol())); },
            [&](auto& id) {
                auto id_stage1 = id;
                auto id_stage2 = ID(fmt("__parse_%s_stage2", p.symbol()));

                std::optional<type::function::Parameter> addl_param;

                if ( ! unit ) // for units, "self" is the destination
                    addl_param = builder::parameter("__dst", type::Auto(), declaration::parameter::Kind::InOut);

                // In the following, we structure the parsing into two
                // stages. Depending on whether the unit may have
                // filtered input, we either put these stages into
                // separate functions where the 1st calls the 2nd (w/
                // filter support); or into just a single joint function
                // doing both (w/o filtering).

                auto run_finally = [&]() {
                    pb->beforeHook();
                    builder()->addMemberCall(state().self, "__on_0x25_finally", {}, p.location());
                    pb->afterHook();

                    if ( unit && unit->contextType() ) {
                        // Unset the context to help break potential reference cycles.
                        builder()->addAssign(builder::member(state().self, "__context"), builder::null());
                    }
                };

                // Helper to wrap future code into a "try" block to catch
                // errors, if necessary.
                auto begin_try = [&](bool insert_try = true) -> std::optional<builder::Builder::TryProxy> {
                    if ( ! (unit && insert_try) )
                        return {};

                    auto x = builder()->addTry();
                    pushBuilder(x.first);
                    return x.second;
                };

                // Helper to close previous "try" block and report
                // errors, if necessary.
                auto end_try = [&](std::optional<builder::Builder::TryProxy>& try_) {
                    if ( ! try_ )
                        return;

                    popBuilder();

                    // We catch *any* exceptions here, not just parse
                    // errors, and not even only HILTI errors. The reason
                    // is that we want a reliable point of error handling
                    // no matter what kind of trouble a Spicy script runs
                    // into.
                    auto catch_ = try_->addCatch();
                    pushBuilder(catch_, [&]() {
                        pb->finalizeUnit(false, p.location());
                        run_finally();
                        builder()->addRethrow();
                    });
                };

                // First stage parse functionality implementing
                // initialization and potentially filtering.
                auto build_parse_stage1_logic = [&]() {
                    if ( unit ) {
                        auto field = p.meta().field();
                        auto type = p.type();

                        std::string msg;

                        if ( field && field->id() )
                            msg = field->id();

                        if ( type && type->typeID() ) {
                            if ( msg.empty() )
                                msg = *type->typeID();
                            else
                                msg = fmt("%s: %s", msg, *type->typeID());
                        }

                        builder()->addDebugMsg("spicy", msg);
                        builder()->addCall("hilti::debugIndent", {builder::string("spicy")});
                    }

                    if ( unit )
                        pb->initializeUnit(p.location());
                };

                auto build_parse_stage1 = [&]() {
                    pushBuilder();

                    auto pstate = state();
                    pstate.self = hilti::expression::UnresolvedID(ID("self"));
                    pstate.data = builder::id("__data");
                    pstate.cur = builder::id("__cur");
                    pstate.ncur = {};
                    pstate.trim = builder::id("__trim");
                    pstate.lahead = builder::id("__lah");
                    pstate.lahead_end = builder::id("__lahe");

                    auto result_type = type::Tuple({type::stream::View(), look_ahead::Type, type::stream::Iterator()});
                    auto store_result = builder()->addTmp("result", result_type);

                    auto try_ = begin_try();

                    if ( unit )
                        pstate.unit = *unit;

                    pushState(std::move(pstate));

                    build_parse_stage1_logic();

                    // Call stage 2.
                    std::vector<Expression> args = {state().data, state().cur, state().trim, state().lahead,
                                                    state().lahead_end};

                    if ( addl_param )
                        args.push_back(builder::id(addl_param->id()));

                    if ( unit && unit->supportsFilters() ) {
                        // If we have a filter attached, we initialize it and change to parse from its output.
                        auto filtered =
                            builder::local("filtered", builder::call("spicy_rt::filter_init",
                                                                     {state().self, state().data, state().cur}));

                        auto [have_filter, not_have_filter] = builder()->addIfElse(filtered);
                        pushBuilder(have_filter);

                        auto args2 = args;
                        builder()->addLocal("filtered_data", type::ValueReference(type::Stream()),
                                            builder::id("filtered"));
                        args2[0] = builder::id("filtered_data");
                        args2[1] = builder::deref(args2[0]);
                        builder()->addExpression(builder::memberCall(state().self, id_stage2, std::move(args2)));

                        // Assume the filter consumed the full input.
                        pb->advanceInput(builder::size(state().cur));

                        auto result = builder::tuple({
                            state().cur,
                            state().lahead,
                            state().lahead_end,
                        });

                        builder()->addAssign(store_result, result);
                        popBuilder();

                        pushBuilder(not_have_filter);
                        builder()->addAssign(store_result,
                                             builder::memberCall(state().self, id_stage2, std::move(args)));
                        popBuilder();
                    }
                    else {
                        builder()->addAssign(store_result,
                                             builder::memberCall(state().self, id_stage2, std::move(args)));
                    }

                    end_try(try_);
                    run_finally();
                    popState();

                    builder()->addReturn(store_result);

                    return popBuilder()->block();
                }; // End of build_parse_stage1()

                // Second stage parse functionality implementing the main
                // part of the unit's parsing.
                auto build_parse_stage2_logic = [&]() {
                    if ( ! unit )
                        pushDestination(builder::id("__dst"));
                    else
                        pushDestination(builder::id("self"));

                    if ( auto x = dispatch(p); ! x )
                        hilti::logger().internalError(
                            fmt("ParserBuilder: non-atomic production %s not handled (%s)", p.typename_(), p));

                    if ( unit )
                        builder()->addCall("hilti::debugDedent", {builder::string("spicy")});

                    auto result = builder::tuple({
                        state().cur,
                        state().lahead,
                        state().lahead_end,
                    });

                    popDestination();
                    return result;
                };

                auto build_parse_stage12_or_stage2 = [&](bool join_stages) {
                    auto pstate = state();
                    pstate.self = hilti::expression::UnresolvedID(ID("self"));
                    pstate.data = builder::id("__data");
                    pstate.cur = builder::id("__cur");
                    pstate.ncur = {};
                    pstate.trim = builder::id("__trim");
                    pstate.lahead = builder::id("__lah");
                    pstate.lahead_end = builder::id("__lahe");

                    if ( unit )
                        pstate.unit = *unit;

                    pushState(std::move(pstate));
                    pushBuilder();

                    auto result_type = type::Tuple({type::stream::View(), look_ahead::Type, type::stream::Iterator()});
                    auto store_result = builder()->addTmp("result", result_type);

                    auto try_ = begin_try(join_stages);

                    if ( join_stages )
                        build_parse_stage1_logic();

                    auto result = build_parse_stage2_logic();
                    builder()->addAssign(store_result, result);

                    end_try(try_);

                    if ( join_stages && unit )
                        run_finally();

                    popState();

                    builder()->addReturn(store_result);

                    return popBuilder()->block();
                }; // End of build_parse_stage2()

                // Add the parse methods. Note the unit's primary
                // stage1 method is already declared (but not
                // implemented) by the struct that unit-builder is
                // declaring.
                if ( unit && unit->supportsFilters() ) {
                    addParseMethod(id_stage1.str() != "__parse_stage1", id_stage1, build_parse_stage1(), addl_param,
                                   p.location());
                    addParseMethod(true, id_stage2, build_parse_stage12_or_stage2(false), addl_param, p.location());
                }
                else
                    addParseMethod(id_stage1.str() != "__parse_stage1", id_stage1, build_parse_stage12_or_stage2(true),
                                   addl_param, p.location());

                return id_stage1;
            });

        std::vector<Expression> args = {
            state().data, state().cur, state().trim, state().lahead, state().lahead_end,
        };

        if ( ! unit )
            args.push_back(destination());

        auto call = builder::memberCall(state().self, id, args);
        builder()->addAssign(builder::tuple({state().cur, state().lahead, state().lahead_end}), call);
    }

    // Returns a boolean expression that's 'true' if a 'stop' was encountered.
    Expression _parseProduction(const Production& p, const production::Meta& meta) {
        const auto is_field_owner = (meta.field() && meta.isFieldProduction() && ! p.isA<production::Resolved>());

        auto field = meta.field();
        assert(field || ! meta.isFieldProduction());

        HILTI_DEBUG(spicy::logging::debug::ParserBuilder, fmt("* production %s", hilti::util::trim(std::string(p))));
        hilti::logging::DebugPushIndent _(spicy::logging::debug::ParserBuilder);

        if ( field ) {
            HILTI_DEBUG(spicy::logging::debug::ParserBuilder,
                        fmt("- field '%s': %s", field->id(), meta.fieldRef()->render(false)));
        }

        if ( const auto& r = p.tryAs<production::Resolved>() )
            // Directly forward, without going through any of the remaining machinery.
            return _parseProduction(grammar.resolved(*r), r->meta());

        // Push destination for parsed value onto stack.

        if ( auto c = meta.container() ) {
            auto etype = type::unit::item::Field::vectorElementTypeThroughSelf(c->id());
            auto container_element = builder()->addTmp("elem", etype);
            pushDestination(container_element);
        }

        else if ( ! meta.isFieldProduction() )
            pushDestination(destination());

        else if ( field->parseType().isA<type::Void>() )
            // No value to store.
            pushDestination(builder::void_());

        else if ( field->isForwarding() ) {
            // No need for a new destination, but we need to initialize the one
            // we have.
            builder()->addAssign(destination(), builder::default_(field->itemType(), field->arguments()));
        }

        else if ( field->isTransient() ) {
            // We won't have a field to store the valule in, create a temporary.
            // auto init = builder::default_(field->itemType(), field->arguments());
            auto dst = builder()->addTmp(fmt("transient_%s", field->id()), field->itemType());
            pushDestination(dst);
        }

        else {
            // Can store parsed value directly in struct field.
            auto dst = builder::member(pb->state().self, field->id());
            pushDestination(dst);
        }

        // Parse production

        if ( is_field_owner )
            preParseField(p, meta);

        beginProduction(p);

        if ( const auto& x = p.tryAs<production::Enclosure>() ) {
            // Recurse.
            parseProduction(x->child());
        }

        else if ( p.atomic() ) {
            // dispatch() will write value to current destination.
            if ( auto x = dispatch(p); ! x )
                hilti::logger().internalError(
                    fmt("ParserBuilder: atomic production %s not handled (%s)", p.typename_(), p));
        }
        else if ( auto unit = p.tryAs<production::Unit>(); unit && *unit->unitType().typeID() != state().unit_id ) {
            // Parsing a different unit type. We call the other unit's parse
            // function, but don't have to create it here.
            std::vector<Expression> args = {pb->state().data, pb->state().cur, pb->state().trim, pb->state().lahead,
                                            pb->state().lahead_end};

            Location location;
            std::vector<Expression> type_args;

            if ( meta.field() ) {
                location = meta.fieldRef()->location();
                type_args = meta.field()->arguments();
            }

            Expression default_ =
                builder::default_(builder::typeByID(*unit->unitType().typeID()), std::move(type_args), location);
            builder()->addAssign(destination(), std::move(default_));

            auto call = builder::memberCall(destination(), "__parse_stage1", std::move(args));
            builder()->addAssign(builder::tuple({pb->state().cur, pb->state().lahead, pb->state().lahead_end}), call);
        }

        else if ( unit )
            parseNonAtomicProduction(p, unit->unitType());
        else
            parseNonAtomicProduction(p, {});

        endProduction(p);

        if ( is_field_owner )
            postParseField(p, meta);

        // Top of stack will now have the final value for the field.
        Expression stop = builder::bool_(false);

        if ( meta.container() ) {
            auto elem = destination();
            popDestination();
            stop = pb->newContainerItem(*meta.container(), destination(), elem, true);
        }

        else if ( ! meta.isFieldProduction() ) {
            // Need to move position ahead.
            if ( state().ncur ) {
                builder()->addAssign(state().cur, *state().ncur);
                state().ncur = {};
            }

            popDestination();
        }

        else if ( field->parseType().isA<type::Void>() )
            popDestination();

        else if ( field->isForwarding() ) {
            // nothing to do
        }

        else if ( field->isTransient() )
            popDestination();

        else
            popDestination();

        return stop;
    }

    void preParseField(const Production& /* i */, const production::Meta& meta) {
        const auto& field = meta.field();
        assert(field); // Must only be called if we have a field.

        HILTI_DEBUG(spicy::logging::debug::ParserBuilder, fmt("- pre-parse field: %s", field->id()));

        if ( field && field->convertExpression() ) {
            // Need an additional temporary for the parsed field.
            auto dst = builder()->addTmp(fmt("parsed_%s", field->id()), field->parseType());
            pushDestination(dst);
        }

        pb->enableDefaultNewValueForField(true);

        if ( auto c = field->condition() )
            pushBuilder(builder()->addIf(*c));

        if ( field->originalType().isA<type::RegExp>() && ! field->isContainer() ) {
            bool needs_captures = true;

            if ( auto ctor_ = field->ctor(); ctor_ && ctor_->as<hilti::ctor::RegExp>().isNoSub() )
                needs_captures = false;

            if ( AttributeSet::find(field->attributes(), "&nosub") )
                needs_captures = false;

            if ( needs_captures ) {
                auto pstate = state();
                pstate.captures = builder()->addTmp("captures", builder::typeByID("hilti::Captures"));
                pushState(std::move(pstate));
            }
        }

        if ( auto a = AttributeSet::find(field->attributes(), "&parse-from") ) {
            // Redirect input to a bytes value.
            auto pstate = state();
            pstate.trim = builder::bool_(false);
            pstate.lahead = builder()->addTmp("parse_lah", look_ahead::Type, look_ahead::None);
            pstate.lahead_end = builder()->addTmp("parse_lahe", type::stream::Iterator());
            auto expr = a->valueAs<Expression>();

            auto tmp = builder()->addTmp("parse_from", type::ValueReference(type::Stream()), *expr);
            pstate.data = tmp;
            pstate.cur = builder()->addTmp("parse_cur", type::stream::View(), builder::deref(tmp));
            pstate.ncur = {};
            builder()->addMemberCall(tmp, "freeze", {});

            pushState(std::move(pstate));
        }

        if ( auto a = AttributeSet::find(field->attributes(), "&parse-at") ) {
            // Redirect input to a stream position.
            auto pstate = state();
            pstate.trim = builder::bool_(false);
            pstate.lahead = builder()->addTmp("parse_lah", look_ahead::Type, look_ahead::None);
            pstate.lahead_end = builder()->addTmp("parse_lahe", type::stream::Iterator());
            auto expr = a->valueAs<Expression>();

            auto cur = builder::memberCall(state().cur, "advance", {*expr});
            pstate.cur = builder()->addTmp("parse_cur", cur);
            pstate.ncur = {};
            pushState(std::move(pstate));
        }

        // `&size` and `&max-size` share the same underlying infrastructure
        // so try to extract both of them and compute the ultimate value.
        std::optional<Expression> length;
        // Only at most one of `&max-size` and `&size` will be set.
        assert(! (AttributeSet::find(field->attributes(), "&size") &&
                  AttributeSet::find(field->attributes(), "&max-size")));
        if ( auto a = AttributeSet::find(field->attributes(), "&size") )
            length = builder::coerceTo(*a->valueAs<Expression>(), type::UnsignedInteger(64));
        if ( auto a = AttributeSet::find(field->attributes(), "&max-size") )
            // Append a sentinel byte for `&max-size` so we can detect reads beyond the expected length.
            length = builder::incrementPrefix(builder::coerceTo(*a->valueAs<Expression>(), type::UnsignedInteger(64)));

        if ( length ) {
            // Limit input to the specified length.
            auto limited = builder()->addTmp("limited", builder::memberCall(state().cur, "limit", {*length}));

            // Establish limited view, remembering position to continue at.
            auto pstate = state();
            pstate.cur = limited;
            pstate.ncur = builder()->addTmp("ncur", builder::memberCall(state().cur, "advance", {*length}));
            pushState(std::move(pstate));
        }
        else {
            auto pstate = state();
            pstate.ncur = {};
            pushState(std::move(pstate));
        }

        if ( pb->options().getAuxOption<bool>("spicy.track_offsets", false) ) {
            auto __offsets = builder::member(state().self, "__offsets");
            auto cur_offset = builder::memberCall(state().cur, "offset", {});

            // Since the offset list is created empty resize the
            // vector so that we can access the current field's index.
            assert(field->index());
            auto index = builder()->addTmp("index", builder::integer(*field->index()));
            builder()->addMemberCall(__offsets, "resize", {builder::sum(index, builder::integer(1))});

            builder()->addAssign(builder::index(__offsets, *field->index()),
                                 builder::tuple({cur_offset, builder::optional(hilti::type::UnsignedInteger(64))}));
        }

        if ( auto a = AttributeSet::find(field->attributes(), "&try") )
            pb->initBacktracking();
    }

    void postParseField(const Production& p, const production::Meta& meta) {
        const auto& field = meta.field();
        assert(field); // Must only be called if we have a field.

        HILTI_DEBUG(spicy::logging::debug::ParserBuilder, fmt("- post-parse field: %s", field->id()));

        if ( auto a = AttributeSet::find(field->attributes(), "&try") )
            pb->finishBacktracking();

        if ( pb->options().getAuxOption<bool>("spicy.track_offsets", false) ) {
            assert(field->index());
            auto __offsets = builder::member(state().self, "__offsets");
            auto cur_offset = builder::memberCall(state().cur, "offset", {});
            auto offsets = builder::index(__offsets, *field->index());
            builder()->addAssign(offsets, builder::tuple({builder::index(builder::deref(offsets), 0), cur_offset}));
        }

        auto ncur = state().ncur;
        state().ncur = {};

        if ( auto a = AttributeSet::find(field->attributes(), "&max-size") ) {
            // Check that we did not read into the sentinel byte.
            auto cond = builder::greaterEqual(builder::memberCall(state().cur, "offset", {}),
                                              builder::memberCall(*ncur, "offset", {}));
            auto exceeded = builder()->addIf(std::move(cond));
            pushBuilder(exceeded, [&]() {
                // We didn't finish parsing the data, which is an error.
                if ( ! destination().type().isA<type::Void>() && ! field->isTransient() )
                    // Clear the field in case the type parsing has started
                    // to fill it.
                    builder()->addExpression(builder::unset(state().self, field->id()));

                pb->parseError("parsing not done within &max-size bytes", a->meta());
            });
        }

        else if ( auto a = AttributeSet::find(field->attributes(), "&size") ) {
            // Make sure we parsed the entire &size amount.
            auto missing = builder::unequal(builder::memberCall(state().cur, "offset", {}),
                                            builder::memberCall(*ncur, "offset", {}));
            auto insufficient = builder()->addIf(std::move(missing));
            pushBuilder(insufficient, [&]() {
                // We didn't parse all the data, which is an error.
                if ( ! destination().type().isA<type::Void>() && ! field->isTransient() )
                    // Clear the field in case the type parsing has started
                    // to fill it.
                    builder()->addExpression(builder::unset(state().self, field->id()));

                pb->parseError("&size amount not consumed", a->meta());
            });
        }

        auto dd = destination();

        if ( field->convertExpression() ) {
            // Value was stored in temporary. Apply expression and store result
            // at destination.
            popDestination();
            pb->applyConvertExpression(*field, dd, destination());
        }

        popState(); // From &size (pushed even if absent).

        if ( AttributeSet::find(field->attributes(), "&parse-from") ||
             AttributeSet::find(field->attributes(), "&parse-at") ) {
            ncur = {};
            popState();
        }

        if ( ncur )
            builder()->addAssign(state().cur, *ncur);

        if ( ! meta.container() ) {
            if ( pb->isEnabledDefaultNewValueForField() && state().literal_mode == LiteralMode::Default )
                pb->newValueForField(meta, destination(), dd);
        }

        if ( state().captures )
            popState();

        if ( field->condition() )
            popBuilder();
    }

    // Returns a boolean expression that's 'true' if a 'stop' was encountered.
    Expression parseProduction(const Production& p) { return _parseProduction(p, p.meta()); }

    // Retrieve a look-ahead symbol. Once the code generated by the function
    // has executed, the parsing state will reflect what look-ahead has been
    // found, including `EOD` if `cur` is the end-of-data, and `None` if no
    // expected look-ahead token is found.
    void getLookAhead(const production::LookAhead& lp) {
        // If we're at EOD, return that directly.
        auto [true_, false_] = builder()->addIfElse(pb->atEod());
        true_->addAssign(state().lahead, look_ahead::Eod);

        pushBuilder(false_);

        // Collect all expected terminals.
        auto& lahs = lp.lookAheads();
        auto tokens = hilti::util::set_union(lahs.first, lahs.second);

        auto regexps = std::vector<Production>();
        auto other = std::vector<Production>();
        std::partition_copy(tokens.begin(), tokens.end(), std::back_inserter(regexps), std::back_inserter(other),
                            [](auto& p) { return p.type()->template isA<hilti::type::RegExp>(); });

        bool first_token = true;

        // Parse regexps in parallel.
        if ( ! regexps.empty() ) {
            first_token = false;

            // Create the joint regular expression. The token IDs become the regexps' IDs.
            auto patterns = hilti::util::transform(regexps, [](const auto& c) {
                return std::make_pair(c.template as<production::Ctor>()
                                          .ctor()
                                          .template as<hilti::ctor::RegExp>()
                                          .value(),
                                      c.tokenID());
            });

            auto flattened = std::vector<std::string>();

            for ( const auto& p : patterns ) {
                for ( const auto& r : p.first )
                    flattened.push_back(hilti::util::fmt("%s{#%" PRId64 "}", r, p.second));
            }

            auto re = hilti::ID(fmt("__re_%" PRId64, lp.symbol()));
            auto d = builder::constant(re, builder::regexp(flattened,
                                                           AttributeSet({Attribute("&nosub"), Attribute("&anchor")})));
            pb->cg()->addDeclaration(d);

            // Create the token matcher state.
            builder()->addLocal(ID("ncur"), state().cur);
            auto ms = builder::local("ms", builder::memberCall(builder::id(re), "token_matcher", {}));

            // Create the loop around the incremental matching.
            auto body = builder()->addWhile(ms, builder::bool_(true));
            pushBuilder(body);

            builder()->addLocal(ID("rc"), hilti::type::SignedInteger(32));

            builder()->addAssign(builder::tuple({builder::id("rc"), builder::id("ncur")}),
                                 builder::memberCall(builder::id("ms"), "advance", {builder::id("ncur")}),
                                 lp.location());

            auto switch_ = builder()->addSwitch(builder::id("rc"), lp.location());

            auto no_match_try_again = switch_.addCase(builder::integer(-1));
            pushBuilder(no_match_try_again);
            auto ok = builder()->addIf(pb->waitForInputOrEod());
            ok->addContinue();
            builder()->addAssign(state().lahead, look_ahead::Eod);
            builder()->addAssign(state().lahead_end, builder::begin(state().cur));
            builder()->addBreak();
            popBuilder();

            auto no_match_error = switch_.addCase(builder::integer(0));
            pushBuilder(no_match_error);
            builder()->addAssign(state().lahead, look_ahead::None);
            builder()->addAssign(state().lahead_end, builder::begin(state().cur));
            builder()->addBreak();
            popBuilder();

            auto match = switch_.addDefault();
            pushBuilder(match);
            builder()->addAssign(state().lahead, builder::id("rc"));
            builder()->addAssign(state().lahead_end, builder::begin(builder::id("ncur")));
            builder()->addBreak();
            popBuilder();

            popBuilder(); // End of switch body
        }

        // Parse non-regexps successively.
        for ( auto& p : other ) {
            if ( ! p.isLiteral() )
                continue;

            auto pstate = pb->state();
            pstate.literal_mode = LiteralMode::Try;
            pushState(std::move(pstate));
            auto match = pb->parseLiteral(p, {});
            popState();

            if ( first_token ) {
                // Simplified version, no previous match possible that we
                // would need to compare against.
                first_token = false;
                auto true_ = builder()->addIf(builder::unequal(match, builder::begin(state().cur)));
                true_->addAssign(state().lahead, builder::integer(p.tokenID()));
                true_->addAssign(state().lahead_end, match);
            }
            else {
                // If the length is larger than any token we have found so
                // far, we take it. If length is the same as previous one,
                // it's ambiguous and we bail out.
                auto true_ =
                    builder()->addIf(builder::local("i", match),
                                     builder::and_(builder::unequal(builder::id("i"), builder::begin(state().cur)),
                                                   builder::greaterEqual(builder::id("i"), state().lahead_end)));

                auto ambiguous = true_->addIf(builder::and_(builder::unequal(state().lahead, look_ahead::None),
                                                            builder::equal(builder::id("i"), state().lahead_end)));
                pushBuilder(ambiguous);
                pb->parseError("ambiguous look-ahead token match", lp.location());
                popBuilder();

                true_->addAssign(state().lahead, builder::integer(p.tokenID()));
                true_->addAssign(state().lahead_end, builder::id("i"));
            }
        }

        popBuilder();
    }

    // Adds a method, and its implementation, to the current parsing struct
    // type that has the standard signature for parse methods.
    void addParseMethod(bool add_decl, const ID& id, Statement body,
                        std::optional<type::function::Parameter> addl_param = {}, const Meta& m = {}) {
        auto qualified_id = pb->state().unit_id + id;

        auto ftype = pb->parseMethodFunctionType(std::move(addl_param), m);
        auto func = builder::function(qualified_id, ftype, std::move(body), declaration::Linkage::Struct,
                                      function::CallingConvention::Standard, {}, m);

        if ( add_decl )
            new_fields.emplace_back(type::struct_::Field(id, func.function().type()));

        cg()->addDeclaration(func);
    }

    void operator()(const production::Epsilon& /* p */) {}

    void operator()(const production::Counter& p) {
        auto body = builder()->addWhile(builder::local("__i", hilti::type::UnsignedInteger(64), p.expression()),
                                        builder::id("__i"));

        pushBuilder(body);
        body->addExpression(builder::decrementPostfix(builder::id("__i")));

        auto stop = parseProduction(p.body());
        auto b = builder()->addIf(stop);
        b->addBreak();
        popBuilder();
    }

    void operator()(const production::Enclosure& p) {
        builder()->addCall("hilti::debugIndent", {builder::string("spicy")});
        parseProduction(p.child());
        builder()->addCall("hilti::debugDedent", {builder::string("spicy")});
    }

    void operator()(const production::ForEach& p) {
        Expression cond;

        if ( p.eodOk() )
            cond = builder::not_(builder::call("spicy_rt::atEod", {state().data, state().cur}));
        else
            cond = builder::bool_(true);

        auto body = builder()->addWhile(cond);
        pushBuilder(body);
        auto stop = parseProduction(p.body());
        auto b = builder()->addIf(stop);
        b->addBreak();
        popBuilder();
    }

    void operator()(const production::Resolved& p) { parseProduction(grammar.resolved(p)); }

    void operator()(const production::Switch& p) {
        builder()->addCall("hilti::debugIndent", {builder::string("spicy")});

        auto switch_ = builder()->addSwitch(p.expression(), p.location());

        for ( const auto& [exprs, prod] : p.cases() ) {
            auto case_ = switch_.addCase(exprs, prod.location());
            pushBuilder(case_, [&, prod = std::ref(prod)]() { parseProduction(prod); });
        }

        if ( auto prod = p.default_() ) {
            auto default_ = switch_.addDefault(prod->location());
            pushBuilder(default_, [&]() { parseProduction(*prod); });
        }
        else {
            auto default_ = switch_.addDefault(p.location());
            pushBuilder(default_, [&]() { pb->parseError("no matching case in switch statement", p.location()); });
        }

        builder()->addCall("hilti::debugDedent", {builder::string("spicy")});
    }

    void operator()(const production::Unit& p) {
        auto pstate = pb->state();
        pstate.self = destination();
        pushState(std::move(pstate));

        if ( p.unitType().usesRandomAccess() ) {
            // Disable trimming.
            auto pstate = state();
            pstate.trim = builder::bool_(false);
            pushState(std::move(pstate));
        }

        // `&size` and `&max-size` share the same underlying infrastructure
        // so try to extract both of them and compute the ultimate value. We
        // already reject cases where `&size` and `&max-size` are combined
        // during validation.
        std::optional<Expression> length;
        // Only at most one of `&max-size` and `&size` will be set.
        assert(! (AttributeSet::find(p.unitType().attributes(), "&size") &&
                  AttributeSet::find(p.unitType().attributes(), "&max-size")));
        if ( auto a = AttributeSet::find(p.unitType().attributes(), "&size") )
            length = builder::coerceTo(*a->valueAs<Expression>(), type::UnsignedInteger(64));
        else if ( auto a = AttributeSet::find(p.unitType().attributes(), "&max-size") )
            // Append a sentinel byte for `&max-size` so we can detect reads beyond the expected length.
            length = builder::incrementPrefix(builder::coerceTo(*a->valueAs<Expression>(), type::UnsignedInteger(64)));

        if ( length ) {
            // Limit input to the specified length.
            auto limited = builder()->addTmp("limited", builder::memberCall(state().cur, "limit", {*length}));

            // Establish limited view, remembering position to continue at.
            auto pstate = state();
            pstate.cur = limited;
            pstate.ncur = builder()->addTmp("ncur", builder::memberCall(state().cur, "advance", {*length}));
            pushState(std::move(pstate));
        }

        for ( const auto& i : p.fields() )
            parseProduction(i);

        pb->finalizeUnit(true, p.location());

        if ( auto a = AttributeSet::find(p.unitType().attributes(), "&max-size") ) {
            // Check that we did not read into the sentinel byte.
            auto cond = builder::greaterEqual(builder::memberCall(state().cur, "offset", {}),
                                              builder::memberCall(*state().ncur, "offset", {}));
            auto exceeded = builder()->addIf(std::move(cond));
            pushBuilder(exceeded, [&]() { pb->parseError("parsing not done within &max-size bytes", a->meta()); });

            // Restore parser state.
            auto ncur = state().ncur;
            popState();
            builder()->addAssign(state().cur, *ncur);
        }

        else if ( auto a = AttributeSet::find(p.unitType().attributes(), "&size") ) {
            // Make sure we parsed the entire &size amount.
            auto missing = builder::unequal(builder::memberCall(state().cur, "offset", {}),
                                            builder::memberCall(*state().ncur, "offset", {}));
            auto insufficient = builder()->addIf(std::move(missing));
            pushBuilder(insufficient, [&]() { pb->parseError("&size amount not consumed", a->meta()); });

            auto ncur = state().ncur;
            popState();
            builder()->addAssign(state().cur, *ncur);
        }

        if ( p.unitType().usesRandomAccess() )
            popState();

        popState();
    }

    void operator()(const production::Ctor& p) { pb->parseLiteral(p, destination()); }

    auto parseLookAhead(const production::LookAhead& p) {
        assert(state().needs_look_ahead);

        // If we don't have a look-ahead symbol pending, get one.
        auto true_ = builder()->addIf(builder::not_(state().lahead));
        pushBuilder(true_);
        getLookAhead(p);
        popBuilder();

        // Now use the freshly set look-ahead symbol to switch accordingly.
        auto& lahs = p.lookAheads();

        auto alts1 = hilti::util::filter(lahs.first, [](const auto& p) { return p.isLiteral(); });
        auto alts2 = hilti::util::filter(lahs.second, [](const auto& p) { return p.isLiteral(); });
        auto exprs_alt1 =
            hilti::util::transform_to_vector(alts1, [](const auto& p) { return builder::integer(p.tokenID()); });
        auto exprs_alt2 =
            hilti::util::transform_to_vector(alts2, [](const auto& p) { return builder::integer(p.tokenID()); });

        switch ( p.default_() ) {
            case production::look_ahead::Default::First: {
                exprs_alt1.push_back(look_ahead::None);
                break;
            }
            case production::look_ahead::Default::Second: {
                exprs_alt2.push_back(look_ahead::None);
                break;
            }
            case production::look_ahead::Default::None: {
                break;
            }
        }

        // If one alternative has no look-aheads and is just epsilon, then
        // EOD is OK and we go there if we haven't found a look-ahead symbol.
        bool eod_handled = true;

        if ( lahs.first.empty() && p.alternatives().first.isA<production::Epsilon>() )
            exprs_alt1.push_back(look_ahead::Eod);
        else if ( lahs.second.empty() && p.alternatives().second.isA<production::Epsilon>() )
            exprs_alt2.push_back(look_ahead::Eod);
        else
            eod_handled = false;

        auto switch_ = builder()->addSwitch(state().lahead);
        auto builder_alt1 = switch_.addCase(std::move(exprs_alt1));
        auto builder_alt2 = switch_.addCase(std::move(exprs_alt2));

        if ( ! eod_handled ) {
            auto builder_eod = switch_.addCase(look_ahead::Eod);
            pushBuilder(builder_eod);
            pb->parseError("expected look-ahead token, but reached end-of-data", p.location());
            popBuilder();
        }

        auto builder_default = switch_.addDefault();
        pushBuilder(builder_default);
        pb->parseError("no expected look-ahead token found", p.location());
        popBuilder();

        return std::make_pair(builder_alt1, builder_alt2);
    }

    void operator()(const production::LookAhead& p) {
        auto [builder_alt1, builder_alt2] = parseLookAhead(p);

        pushBuilder(builder_alt1);
        parseProduction(p.alternatives().first);
        popBuilder();

        pushBuilder(builder_alt2);
        parseProduction(p.alternatives().second);
        popBuilder();
    }

    void operator()(const production::Sequence& p) {
        for ( const auto& i : p.sequence() )
            parseProduction(i);
    }

    void operator()(const production::Variable& p) { pb->parseType(p.type(), p.meta(), destination()); }

    void operator()(const production::While& p) {
        if ( p.expression() )
            hilti::logger().internalError("expression-based while loop not implemented in parser builder");
        else {
            // Look-ahead based loop.
            auto body = builder()->addWhile(hilti::builder::bool_(true));
            pushBuilder(body, [&]() {
                // If we don't have any input right now, we suspend because
                // we might get an EOD next, in which case we need to abort the loop.
                builder()->addExpression(pb->waitForInputOrEod(builder::integer(1)));

                auto lah_prod = p.lookAheadProduction();
                auto [builder_alt1, builder_alt2] = parseLookAhead(lah_prod);

                pushBuilder(builder_alt1, [&]() {
                    // Terminate loop.
                    builder()->addBreak();
                });

                pushBuilder(builder_alt2, [&]() {
                    // Parse body.
                    parseProduction(p.body());
                });
            });
        };
    }
};

} // namespace spicy::detail::codegen

static auto parseMethodIDs(const type::Unit& t) {
    assert(t.typeID());
    return std::make_tuple(ID(fmt("%s::parse1", *t.typeID())), ID(fmt("%s::parse2", *t.typeID())),
                           ID(fmt("%s::parse3", *t.typeID())), ID(fmt("%s::context_new", *t.typeID())));
}

hilti::type::Function ParserBuilder::parseMethodFunctionType(std::optional<type::function::Parameter> addl_param,
                                                             const Meta& m) {
    auto result = type::Tuple({type::stream::View(), look_ahead::Type, type::stream::Iterator()});

    auto params = std::vector<type::function::Parameter>{
        builder::parameter("__data", type::ValueReference(type::Stream()), declaration::parameter::Kind::InOut),
        builder::parameter("__cur", type::stream::View(), declaration::parameter::Kind::Copy),
        builder::parameter("__trim", type::Bool(), declaration::parameter::Kind::Copy),
        builder::parameter("__lah", look_ahead::Type, declaration::parameter::Kind::Copy),
        builder::parameter("__lahe", type::stream::Iterator(), declaration::parameter::Kind::Copy),
    };

    if ( addl_param )
        params.push_back(*addl_param);

    return type::Function(type::function::Result(std::move(result), m), params, hilti::type::function::Flavor::Method,
                          m);
}

const std::shared_ptr<hilti::Context>& ParserBuilder::context() const { return _cg->context(); }

const hilti::Options& ParserBuilder::options() const { return _cg->options(); }

std::shared_ptr<hilti::builder::Builder> ParserBuilder::pushBuilder() {
    _builders.emplace_back(std::make_shared<hilti::builder::Builder>(context()));
    return _builders.back();
}

hilti::type::Struct ParserBuilder::addParserMethods(hilti::type::Struct s, const type::Unit& t, bool declare_only) {
    auto [id_ext_overload1, id_ext_overload2, id_ext_overload3, id_ext_context_new] = parseMethodIDs(t);

    std::vector<type::function::Parameter> params =
        {builder::parameter("data", type::ValueReference(type::Stream()), declaration::parameter::Kind::InOut),
         builder::parameter("cur", type::Optional(type::stream::View()), builder::optional(type::stream::View())),
         builder::parameter("context", type::Optional(builder::typeByID("spicy_rt::UnitContext")))};

    for ( auto p : t.parameters() )
        params.emplace_back(p);

    auto f_ext_overload1_result = type::stream::View();
    auto f_ext_overload1 =
        builder::function(id_ext_overload1, f_ext_overload1_result, std::move(params), type::function::Flavor::Method,
                          declaration::Linkage::Struct, function::CallingConvention::Extern,
                          AttributeSet({Attribute("&static")}), t.meta());

    auto f_ext_overload2_result = type::stream::View();
    auto f_ext_overload2 =
        builder::function(id_ext_overload2, f_ext_overload2_result,
                          {builder::parameter("unit", hilti::type::UnresolvedID(*t.typeID()),
                                              declaration::parameter::Kind::InOut),
                           builder::parameter("data", type::ValueReference(type::Stream()),
                                              declaration::parameter::Kind::InOut),
                           builder::parameter("cur", type::Optional(type::stream::View()),
                                              builder::optional(type::stream::View())),
                           builder::parameter("context", type::Optional(builder::typeByID("spicy_rt::UnitContext")))},
                          type::function::Flavor::Method, declaration::Linkage::Struct,
                          function::CallingConvention::Extern, AttributeSet({Attribute("&static")}), t.meta());

    auto f_ext_overload3_result = type::stream::View();
    auto f_ext_overload3 =
        builder::function(id_ext_overload3, f_ext_overload3_result,
                          {builder::parameter("gunit", type::ValueReference(builder::typeByID("spicy_rt::ParsedUnit")),
                                              declaration::parameter::Kind::InOut),
                           builder::parameter("data", type::ValueReference(type::Stream()),
                                              declaration::parameter::Kind::InOut),
                           builder::parameter("cur", type::Optional(type::stream::View()),
                                              builder::optional(type::stream::View())),
                           builder::parameter("context", type::Optional(builder::typeByID("spicy_rt::UnitContext")))},
                          type::function::Flavor::Method, declaration::Linkage::Struct,
                          function::CallingConvention::Extern, AttributeSet({Attribute("&static")}), t.meta());

    auto f_ext_context_new_result = builder::typeByID("spicy_rt::UnitContext");
    auto f_ext_context_new =
        builder::function(id_ext_context_new, f_ext_context_new_result, {}, type::function::Flavor::Method,
                          declaration::Linkage::Struct, function::CallingConvention::ExternNoSuspend,
                          AttributeSet({Attribute("&static")}), t.meta());

    // We only actually add the functions we just build if the unit is
    // publicly exposed. We still build their code in either case below
    // because doing so triggers generation of the whole parser, including
    // the internal parsing functions.
    auto sf_ext_overload1 =
        type::struct_::Field(f_ext_overload1.id().local(), function::CallingConvention::Extern,
                             f_ext_overload1.function().type(), f_ext_overload1.function().attributes());
    auto sf_ext_overload2 =
        type::struct_::Field(f_ext_overload2.id().local(), function::CallingConvention::Extern,
                             f_ext_overload2.function().type(), f_ext_overload2.function().attributes());

    auto sf_ext_overload3 =
        type::struct_::Field(f_ext_overload3.id().local(), function::CallingConvention::Extern,
                             f_ext_overload3.function().type(), f_ext_overload3.function().attributes());

    s = hilti::type::Struct::addField(s, sf_ext_overload1);
    s = hilti::type::Struct::addField(s, sf_ext_overload2);
    s = hilti::type::Struct::addField(s, sf_ext_overload3);

    if ( auto ctx = t.contextType() ) {
        auto sf_ext_ctor =
            type::struct_::Field(f_ext_context_new.id().local(), function::CallingConvention::Extern,
                                 f_ext_context_new.function().type(), f_ext_context_new.function().attributes());

        s = hilti::type::Struct::addField(s, sf_ext_ctor);
    }

    if ( ! declare_only ) {
        // Helper to initialize a unit's __context attribute. We use
        // a parse functions "context" argument if that was provided,
        // and otherwise create a default instanc of the unit's context type.
        auto init_context = [&]() {
            auto context = t.contextType();
            if ( ! context )
                return;

            auto arg_ctx = builder::id("context");
            auto create_ctx = builder::memberCall(builder::id("unit"), "context_new", {});
            auto ctx = builder::ternary(arg_ctx, builder::deref(arg_ctx), create_ctx);

            builder()->addCall("spicy_rt::setContext",
                               {builder::member(builder::id("unit"), "__context"), ctx, builder::typeinfo(*context)});
        };

        HILTI_DEBUG(spicy::logging::debug::ParserBuilder, fmt("creating parser for %s", *t.typeID()));
        hilti::logging::DebugPushIndent _(spicy::logging::debug::ParserBuilder);

        auto grammar = cg()->grammarBuilder()->grammar(t);
        auto visitor = ProductionVisitor(this, grammar);

        if ( t.parameters().empty() ) {
            // Create parse1() body.
            pushBuilder();
            builder()->addLocal("unit", builder::value_reference(
                                            builder::default_(builder::typeByID(*t.typeID()),
                                                              hilti::util::transform(t.parameters(), [](auto p) {
                                                                  return builder::id(p.id());
                                                              }))));
            builder()->addLocal("ncur", type::stream::View(),
                                builder::ternary(builder::id("cur"), builder::deref(builder::id("cur")),
                                                 builder::cast(builder::deref(builder::id("data")),
                                                               type::stream::View())));
            builder()->addLocal("lahead", look_ahead::Type, look_ahead::None);
            builder()->addLocal("lahead_end", type::stream::Iterator());

            init_context();

            auto pstate = ParserState(t, grammar, builder::id("data"), builder::id("cur"));
            pstate.self = builder::id("unit");
            pstate.cur = builder::id("ncur");
            pstate.trim = builder::bool_(true);
            pstate.lahead = builder::id("lahead");
            pstate.lahead_end = builder::id("lahead_end");
            pushState(pstate);
            visitor.pushDestination(pstate.self);
            visitor.parseProduction(*grammar.root());
            builder()->addReturn(state().cur);
            popState();

            auto body_ext_overload1 = popBuilder();
            auto d_ext_overload1 = hilti::declaration::Function::setBody(f_ext_overload1, body_ext_overload1->block());
            cg()->addDeclaration(d_ext_overload1);

            // Create parse3() body.
            pushBuilder();
            builder()->addLocal("unit", builder::value_reference(
                                            builder::default_(builder::typeByID(*t.typeID()),
                                                              hilti::util::transform(t.parameters(), [](auto p) {
                                                                  return builder::id(p.id());
                                                              }))));

            builder()->addCall(ID("spicy_rt::initializeParsedUnit"),
                               {builder::id("gunit"), builder::id("unit"), builder::typeinfo(t)});
            builder()->addLocal("ncur", type::stream::View(),
                                builder::ternary(builder::id("cur"), builder::deref(builder::id("cur")),
                                                 builder::cast(builder::deref(builder::id("data")),
                                                               type::stream::View())));
            builder()->addLocal("lahead", look_ahead::Type, look_ahead::None);
            builder()->addLocal("lahead_end", type::stream::Iterator());

            init_context();

            pstate = ParserState(t, grammar, builder::id("data"), builder::id("cur"));
            pstate.self = builder::id("unit");
            pstate.cur = builder::id("ncur");
            pstate.trim = builder::bool_(true);
            pstate.lahead = builder::id("lahead");
            pstate.lahead_end = builder::id("lahead_end");
            pushState(pstate);
            visitor.pushDestination(pstate.self);
            visitor.parseProduction(*grammar.root());
            builder()->addReturn(state().cur);

            popState();

            auto body_ext_overload3 = popBuilder();
            auto d_ext_overload3 = hilti::declaration::Function::setBody(f_ext_overload3, body_ext_overload3->block());
            cg()->addDeclaration(d_ext_overload3);
        }

        // Create parse2() body.
        pushBuilder();
        builder()->addLocal("ncur", type::stream::View(),
                            builder::ternary(builder::id("cur"), builder::deref(builder::id("cur")),
                                             builder::cast(builder::deref(builder::id("data")), type::stream::View())));
        builder()->addLocal("lahead", look_ahead::Type, look_ahead::None);
        builder()->addLocal("lahead_end", type::stream::Iterator());

        init_context();

        auto pstate = ParserState(t, grammar, builder::id("data"), builder::id("cur"));
        pstate.self = builder::id("unit");
        pstate.cur = builder::id("ncur");
        pstate.trim = builder::bool_(true);
        pstate.lahead = builder::id("lahead");
        pstate.lahead_end = builder::id("lahead_end");
        pushState(pstate);
        visitor.pushDestination(pstate.self);
        visitor.parseProduction(*grammar.root());
        builder()->addReturn(state().cur);
        popState();

        auto body_ext_overload2 = popBuilder();

        auto d_ext_overload2 = hilti::declaration::Function::setBody(f_ext_overload2, body_ext_overload2->block());
        cg()->addDeclaration(d_ext_overload2);

        if ( auto ctx = t.contextType() ) {
            // Create context_new() body.
            pushBuilder();
            auto obj = builder::new_(*ctx);
            auto ti = hilti::builder::typeinfo(*ctx);
            builder()->addReturn(builder::call("spicy_rt::createContext", {std::move(obj), std::move(ti)}));
            auto body_ext_context_new = popBuilder();

            auto d_ext_context_new =
                hilti::declaration::Function::setBody(f_ext_context_new, body_ext_context_new->block());
            cg()->addDeclaration(d_ext_context_new);
        }

        for ( auto f : visitor.new_fields )
            s = hilti::type::Struct::addField(s, std::move(f));
    }

    return s;
}

Expression ParserBuilder::parseMethodExternalOverload1(const type::Unit& t) {
    auto id = std::get<0>(parseMethodIDs(t));
    return hilti::expression::UnresolvedID(std::move(id));
}

Expression ParserBuilder::parseMethodExternalOverload2(const type::Unit& t) {
    auto id = std::get<1>(parseMethodIDs(t));
    return hilti::expression::UnresolvedID(std::move(id));
}

Expression ParserBuilder::parseMethodExternalOverload3(const type::Unit& t) {
    auto id = std::get<2>(parseMethodIDs(t));
    return hilti::expression::UnresolvedID(std::move(id));
}

Expression ParserBuilder::contextNewFunction(const type::Unit& t) {
    auto id = std::get<3>(parseMethodIDs(t));
    return hilti::expression::UnresolvedID(std::move(id));
}

void ParserBuilder::newValueForField(const production::Meta& meta, const Expression& value, const Expression& dd) {
    const auto& field = meta.field();

    if ( value.type().isA<type::Void>() ) {
        // Special-case: No value parsed, but still run hook.
        beforeHook();
        builder()->addMemberCall(state().self, ID(fmt("__on_%s", field->id().local())), {}, field->meta());
        afterHook();
        return;
    }

    for ( const auto& a : AttributeSet::findAll(field->attributes(), "&requires") ) {
        // We evaluate "&requires" here so that the field's value has been
        // set already, and is hence accessible to the condition through
        // "self.<x>".
        auto block = builder()->addBlock();
        block->addLocal(ID("__dd"), field->parseType(), dd);
        auto cond = block->addTmp("requires", *a.valueAs<Expression>());
        pushBuilder(block->addIf(builder::not_(cond)), [&]() { parseError("&requires failed", a.value().location()); });
    }

    if ( ! field->parseType().isA<spicy::type::Bitfield>() ) {
        builder()->addDebugMsg("spicy", fmt("%s = %%s", field->id()), {value});
        builder()->addDebugMsg("spicy-verbose", fmt("- setting field '%s' to '%%s'", field->id()), {value});
    }

    for ( const auto& s : field->sinks() ) {
        builder()->addDebugMsg("spicy-verbose", "- writing %" PRIu64 " bytes to sink", {builder::size(value)});
        builder()->addMemberCall(builder::deref(s), "write", {value, builder::null(), builder::null()}, field->meta());
    }

    if ( field->emitHook() ) {
        beforeHook();

        std::vector<Expression> args = {std::move(value)};

        if ( field->originalType().isA<type::RegExp>() && ! field->isContainer() ) {
            if ( state().captures )
                args.push_back(*state().captures);
            else
                args.push_back(hilti::builder::default_(builder::typeByID("hilti::Captures")));
        }

        builder()->addMemberCall(state().self, ID(fmt("__on_%s", field->id().local())), std::move(args), field->meta());

        afterHook();
    }

    return;
}

Expression ParserBuilder::newContainerItem(const type::unit::item::Field& field, const Expression& self,
                                           const Expression& item, bool need_value) {
    auto stop = builder()->addTmp("stop", builder::bool_(false));

    auto push_element = [&]() {
        if ( need_value )
            pushBuilder(builder()->addIf(builder::not_(stop)),
                        [&]() { builder()->addExpression(builder::memberCall(self, "push_back", {item})); });
    };

    auto run_hook = [&]() {
        builder()->addDebugMsg("spicy-verbose", "- got container item");
        pushBuilder(builder()->addIf(builder::not_(stop)), [&]() {
            if ( field.emitHook() ) {
                beforeHook();
                builder()->addMemberCall(state().self, ID(fmt("__on_%s_foreach", field.id().local())), {item, stop},
                                         field.meta());
                afterHook();
            }
        });
    };

    auto eval_condition = [&](const Expression& cond) {
        pushBuilder(builder()->addBlock(), [&]() {
            builder()->addLocal("__dd", item);
            builder()->addAssign(stop, builder::or_(stop, cond));
        });
    };

    if ( auto a = AttributeSet::find(field.attributes(), "&until") ) {
        eval_condition(*a->valueAs<spicy::Expression>());
        run_hook();
        push_element();
    }

    else if ( auto a = AttributeSet::find(field.attributes(), "&until-including") ) {
        run_hook();
        push_element();
        eval_condition(*a->valueAs<spicy::Expression>());
    }

    else if ( auto a = AttributeSet::find(field.attributes(), "&while") ) {
        eval_condition(builder::not_(*a->valueAs<spicy::Expression>()));
        run_hook();
        push_element();
    }
    else {
        run_hook();
        push_element();
    }

    return stop;
}

Expression ParserBuilder::applyConvertExpression(const type::unit::item::Field& field, const Expression& value,
                                                 std::optional<Expression> dst) {
    auto convert = field.convertExpression();
    if ( ! convert )
        return value;

    if ( ! dst )
        dst = builder()->addTmp("converted", field.itemType());

    if ( convert->second ) {
        auto block = builder()->addBlock();
        block->addLocal(ID("__dd"), field.parseType(), value);
        block->addAssign(*dst, convert->first);
    }
    else
        // Unit got its own __convert() method for us to call.
        builder()->addAssign(*dst, builder::memberCall(value, "__convert", {}));

    return *dst;
}

void ParserBuilder::trimInput(bool force) {
    auto do_trim = [this](const auto& builder) {
        builder->addDebugMsg("spicy-verbose", "- trimming input");
        builder->addExpression(builder::memberCall(state().data, "trim", {builder::begin(state().cur)}));
    };

    if ( force )
        do_trim(builder());
    else
        do_trim(builder()->addIf(state().trim));
}

void ParserBuilder::initializeUnit(const Location& l) {
    const auto& unit = state().unit.get();

    if ( unit.usesRandomAccess() ) {
        // Save the current input offset for the raw access methods.
        builder()->addAssign(builder::member(state().self, ID("__begin")), builder::begin(state().cur));
        builder()->addAssign(builder::member(state().self, ID("__position")), builder::begin(state().cur));
    }

    beforeHook();
    builder()->addMemberCall(state().self, "__on_0x25_init", {}, l);
    afterHook();
}

void ParserBuilder::finalizeUnit(bool success, const Location& l) {
    const auto& unit = state().unit.get();

    if ( success ) {
        // We evaluate any "&requires" before running the final "%done" hook
        // so that (1) that one can rely on the condition, and (2) we keep
        // running either "%done" or "%error".
        for ( auto attr : AttributeSet::findAll(unit.attributes(), "&requires") ) {
            auto cond = *attr.valueAs<Expression>();
            pushBuilder(builder()->addIf(builder::not_(cond)), [&]() { parseError("&requires failed", cond.meta()); });
        }
    }

    if ( success ) {
        beforeHook();
        builder()->addMemberCall(state().self, "__on_0x25_done", {}, l);
        afterHook();
    }
    else
        builder()->addMemberCall(state().self, "__on_0x25_error", {}, l);

    if ( unit.supportsFilters() )
        builder()->addCall("spicy_rt::filter_disconnect", {state().self});

    if ( unit.isFilter() )
        builder()->addCall("spicy_rt::filter_forward_eod", {state().self});

    for ( const auto& s : unit.items<type::unit::item::Sink>() )
        builder()->addMemberCall(builder::member(state().self, s.id()), "close", {}, l);
}

static Expression _filters(const ParserState& state) {
    hilti::Expression filters;

    if ( state.unit.get().supportsFilters() )
        return builder::member(state.self, ID("__filters"));

    return builder::null();
}

Expression ParserBuilder::waitForInputOrEod() {
    return builder::call("spicy_rt::waitForInputOrEod", {state().data, state().cur, _filters(state())});
}

Expression ParserBuilder::atEod() { return builder::call("spicy_rt::atEod", {state().data, state().cur}); }

void ParserBuilder::waitForInput(const std::string& error_msg, const Meta& location) {
    builder()->addCall("spicy_rt::waitForInput", {state().data, state().cur, builder::string(error_msg),
                                                  builder::expression(location), _filters(state())});
}

Expression ParserBuilder::waitForInputOrEod(const Expression& min) {
    return builder::call("spicy_rt::waitForInputOrEod", {state().data, state().cur, min, _filters(state())});
}

void ParserBuilder::waitForInput(const Expression& min, const std::string& error_msg, const Meta& location) {
    builder()->addCall("spicy_rt::waitForInput", {state().data, state().cur, min, builder::string(error_msg),
                                                  builder::expression(location), _filters(state())});
}

void ParserBuilder::waitForEod() {
    builder()->addCall("spicy_rt::waitForEod", {state().data, state().cur, _filters(state())});
}

void ParserBuilder::parseError(const Expression& error_msg, const Meta& location) {
    builder()->addThrow(builder::exception(builder::typeByID("spicy_rt::ParseError"), error_msg, location), location);
}

void ParserBuilder::parseError(const std::string& error_msg, const Meta& location) {
    parseError(builder::string(error_msg), location);
}

void ParserBuilder::parseError(const std::string& fmt, std::vector<Expression> args, const Meta& location) {
    parseError(builder::modulo(builder::string(fmt), builder::tuple(std::move(args))), location);
}

void ParserBuilder::advanceInput(const Expression& i) {
    if ( i.type().isA<hilti::type::stream::View>() )
        builder()->addAssign(state().cur, i);
    else
        builder()->addAssign(state().cur, builder::memberCall(state().cur, "advance", {i}));

    trimInput();
}

void ParserBuilder::setInput(const Expression& i) { builder()->addAssign(state().cur, i); }

void ParserBuilder::beforeHook() {
    if ( state().unit.get().usesRandomAccess() )
        builder()->addAssign(builder::member(state().self, ID("__position_update")),
                             builder::optional(hilti::type::stream::Iterator()));
}

void ParserBuilder::afterHook() {
    if ( state().unit.get().usesRandomAccess() ) {
        auto position_update = builder::member(state().self, ID("__position_update"));
        auto advance = builder()->addIf(position_update);
        auto ncur = builder::memberCall(state().cur, "advance", {builder::deref(position_update)});

        if ( state().ncur )
            advance->addAssign(*state().ncur, ncur);
        else
            advance->addAssign(state().cur, ncur);

        advance->addAssign(builder::member(state().self, ID("__position_update")),
                           builder::optional(hilti::type::stream::Iterator()));
    }
}

void ParserBuilder::saveParsePosition() {
    if ( ! state().unit.get().usesRandomAccess() )
        return;

    builder()->addAssign(builder::member(state().self, ID("__position")), builder::begin(state().cur));
}

void ParserBuilder::consumeLookAhead(std::optional<Expression> dst) {
    builder()->addDebugMsg("spicy-verbose", "- consuming look-ahead token");

    if ( dst )
        builder()->addAssign(*dst, builder::memberCall(state().cur, "sub", {state().lahead_end}));

    builder()->addAssign(state().lahead, look_ahead::None);
    advanceInput(state().lahead_end);
}

void ParserBuilder::initBacktracking() {
    auto try_cur = builder()->addTmp("try_cur", state().cur);
    auto [body, try_] = builder()->addTry();
    auto catch_ = try_.addCatch(builder::parameter(ID("e"), builder::typeByID("spicy_rt::Backtrack")));
    pushBuilder(catch_, [&]() { builder()->addAssign(state().cur, try_cur); });

    auto pstate = state();
    pstate.trim = builder::bool_(false);
    pushState(std::move(pstate));
    pushBuilder(body);
}

void ParserBuilder::finishBacktracking() {
    popBuilder();
    popState();
    trimInput();
}
