// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <algorithm>
#include <numeric>
#include <optional>
#include <ranges>
#include <utility>

#include <hilti/ast/builder/all.h>
#include <hilti/ast/ctors/regexp.h>
#include <hilti/ast/declarations/field.h>
#include <hilti/ast/declarations/local-variable.h>
#include <hilti/ast/expressions/ctor.h>
#include <hilti/ast/expressions/logical-or.h>
#include <hilti/ast/expressions/name.h>
#include <hilti/ast/expressions/type-wrapped.h>
#include <hilti/ast/expressions/void.h>
#include <hilti/ast/statements/declaration.h>
#include <hilti/ast/types/bitfield.h>
#include <hilti/ast/types/exception.h>
#include <hilti/ast/types/integer.h>
#include <hilti/ast/types/stream.h>
#include <hilti/ast/types/struct.h>
#include <hilti/base/cache.h>
#include <hilti/base/logger.h>
#include <hilti/base/util.h>
#include <hilti/compiler/context.h>

#include <spicy/ast/types/unit-items/field.h>
#include <spicy/ast/types/unit-items/sink.h>
#include <spicy/ast/visitor.h>
#include <spicy/compiler/detail/codegen/codegen.h>
#include <spicy/compiler/detail/codegen/grammar.h>
#include <spicy/compiler/detail/codegen/parser-builder.h>
#include <spicy/compiler/detail/codegen/production.h>
#include <spicy/compiler/detail/codegen/productions/all.h>
#include <spicy/compiler/detail/codegen/productions/visitor.h>

using namespace spicy;
using namespace spicy::detail;
using namespace spicy::detail::codegen;
using hilti::util::fmt;


namespace spicy::logging::debug {
inline const hilti::logging::DebugStream ParserBuilder("parser-builder");
} // namespace spicy::logging::debug

ParserState::ParserState(Builder* builder, type::Unit* unit, const Grammar& grammar, Expression* data, Expression* cur)
    : unit(unit),
      unit_id(unit->typeID()),
      self(builder->expressionName(ID("self"))),
      data(data),
      begin(builder->begin(cur)),
      cur(cur),
      lahead(builder->integer(look_ahead::None)) {}

void ParserState::printDebug(Builder* builder) const {
    builder->addCall("spicy_rt::printParserState",
                     {builder->stringLiteral(unit_id.str()), data, begin, cur, lahead, lahead_end,
                      builder->stringLiteral(to_string(literal_mode)), trim, error});
}

namespace spicy::detail::codegen {

struct ProductionVisitor : public production::Visitor {
    ProductionVisitor(ParserBuilder* pb, const Grammar& g) : pb(pb), grammar(g) {}

    ParserBuilder* pb;
    const Grammar& grammar;
    hilti::util::Cache<std::string, ID> parse_functions;
    std::vector<hilti::declaration::Field*> new_fields;
    std::vector<std::pair<Expression*, Expression*>> destinations; // (value, target for assignment)
    std::vector<ID> path;                                          // paths of IDs followed to get to current unit/field

    auto cg() { return pb->cg(); }
    auto context() { return cg()->context(); }
    const auto& state() { return pb->state(); }

    void pushState(ParserState p) { pb->pushState(std::move(p)); }
    void popState() { pb->popState(); }

    auto builder() { return pb->builder(); }
    auto pushBuilder() { return pb->pushBuilder(); }
    template<typename Func>
    auto pushBuilder(std::shared_ptr<Builder> b, Func&& func) {
        return pb->pushBuilder(std::move(b), func);
    }
    auto pushBuilder(std::shared_ptr<Builder> b) { return pb->pushBuilder(std::move(b)); }
    auto popBuilder() { return pb->popBuilder(); }

    // Returns the current destination from the top of the stack. If
    // `need_assignable_target` is true, returns a value that can be assigned
    // to; otherwise returns a value for which only reading or
    // modifying-in-place is guaranteed to work.
    auto destination(bool need_assignable_target = false) {
        return need_assignable_target ? destinations.back().second : destinations.back().first;
    }

    // Pushes a new destination onto the stack. By default, it is assumed the
    // expression can both read from and assigned to. If the expression is not
    // assignable, `assignable_target` must be provided and will be recorded as
    // yielding a target that can be used for assigning to the destination.
    auto pushDestination(Expression* e, Expression* assignable_target = nullptr) {
        if ( ! assignable_target )
            assignable_target = e;

        HILTI_DEBUG(spicy::logging::debug::ParserBuilder, fmt("- push destination: %s / %s", *e, *assignable_target));
        destinations.emplace_back(e, assignable_target);
    }

    // Pops the most recent destination from the stack.
    void popDestination() {
        destinations.pop_back();

        if ( destinations.size() ) {
            HILTI_DEBUG(spicy::logging::debug::ParserBuilder, fmt("- pop destination, now: %s", *destination()));
        }
        else
            HILTI_DEBUG(spicy::logging::debug::ParserBuilder, fmt("- pop destination, now: none"));
    }

    // Creates a new temporary variable of a given type and pushes that onto
    // the destination stack. If the type takes parameters we wrap it into an
    // unset optional because we can't default instantiate it. In that case, we
    // push a deref operation to the destination stack for reading the value,
    // so that usage remains transparent.
    void pushTmpDestination(const std::string& prefix, QualifiedType* t) {
        if ( ! t->type()->parameters().empty() ) {
            auto* dst = builder()->addTmp(prefix, builder()->typeOptional(t));
            pushDestination(builder()->deref(dst), dst);
        }
        else {
            auto* dst = builder()->addTmp(prefix, t);
            pushDestination(dst);
        }
    }

    // RAII helper to update the visitor's `_path` as we descend the parse tree.
    class PathTracker {
    public:
        PathTracker(std::vector<ID>* path, const ID& id) : _path(path) { path->emplace_back(id); }
        PathTracker() = delete;
        ~PathTracker() {
            if ( _path )
                _path->pop_back();
        }

        PathTracker(const PathTracker& other) = delete;
        PathTracker(PathTracker&& other) noexcept {
            _path = other._path;
            other._path = nullptr;
        }

        PathTracker& operator=(const PathTracker& other) = delete;
        PathTracker& operator=(PathTracker&& other) noexcept {
            if ( this == &other )
                return *this;

            _path = other._path;
            other._path = nullptr;
            return *this;
        }

    private:
        std::vector<ID>* _path = nullptr;
    };

    void beginProduction(const Production& p) {
        HILTI_DEBUG(spicy::logging::debug::ParserBuilder, fmt("- begin production"));

        builder()->addComment(fmt("Begin parsing production: %s", hilti::util::trim(std::string(p))),
                              hilti::statement::comment::Separator::Before);
        if ( pb->options().debug ) {
            pb->state().printDebug(builder());
            builder()->addDebugMsg("spicy-verbose", fmt("- parsing production: %s", hilti::util::trim(std::string(p))));
            builder()->addCall("hilti::debugIndent", {builder()->stringLiteral("spicy-verbose")});
        }
    }

    void endProduction(const Production& p) {
        HILTI_DEBUG(spicy::logging::debug::ParserBuilder, fmt("- end production"));

        if ( pb->options().debug )
            builder()->addCall("hilti::debugDedent", {builder()->stringLiteral("spicy-verbose")});

        builder()->addComment(fmt("End parsing production: %s", hilti::util::trim(std::string(p))),
                              hilti::statement::comment::Separator::After);
    }

    void _checkSizeAmount(Expression* want, const Meta& attr_meta, Expression* ncur,
                          type::unit::item::Field* field = nullptr) {
        // Make sure we parsed the entire &size amount.
        auto* missing =
            builder()->lower(builder()->memberCall(state().cur, "offset"), builder()->memberCall(ncur, "offset"));
        auto insufficient = builder()->addIf(missing);
        pushBuilder(std::move(insufficient), [&]() {
            if ( field && ! field->isAnonymous() && ! field->isSkip() )
                // Clear the field in case the type parsing has started
                // to fill it.
                builder()->addExpression(builder()->unset(state().self, field->id()));

            auto* got = builder()->difference(builder()->memberCall(state().cur, "offset"),
                                              builder()->grouping(
                                                  builder()->difference(builder()->memberCall(ncur, "offset"), want)));
            pb->parseError("&size amount not consumed: expected %" PRIu64 " bytes, but got %" PRIu64 " bytes",
                           {want, got}, attr_meta);
        });
    }

    void parseNonAtomicProduction(const Production& p, type::Unit* unit) {
        // We wrap the parsing of a non-atomic production into a new
        // function that's cached and reused. This ensures correct
        // operation for productions that recurse.
        const auto& id = parse_functions.getOrCreate(
            p.symbol(),
            [&]() {
                return unit ? ID(HILTI_INTERNAL_ID("parse_stage1")) :
                              ID(fmt(HILTI_INTERNAL_ID("parse_%s_stage1"), p.symbol()));
            },
            [&](auto& id) {
                auto id_stage1 = id;
                auto id_stage2 = ID(fmt(HILTI_INTERNAL_ID("parse_%s_stage2"), p.symbol()));

                hilti::type::function::Parameter* addl_param = nullptr;

                if ( ! unit && p.meta().field() ) // for units, "self" is the destination
                    addl_param = builder()->parameter(HILTI_INTERNAL_ID("dst"), p.meta().field()->parseType()->type(),
                                                      hilti::parameter::Kind::InOut);

                // In the following, we structure the parsing into two
                // stages. Depending on whether the unit may have
                // filtered input, we either put these stages into
                // separate functions where the 1st calls the 2nd (w/
                // filter support); or into just a single joint function
                // doing both (w/o filtering).

                auto run_finally = [&]() {
                    pb->beforeHook();
                    builder()->addMemberCall(state().self, HILTI_INTERNAL_ID("on_0x25_finally"), {}, p.location());
                    pb->afterHook();

                    if ( unit && unit->contextType() ) {
                        // Unset the context to help break potential reference cycles.
                        builder()->addAssign(builder()->member(state().self, HILTI_INTERNAL_ID("context")),
                                             builder()->null());
                    }
                };

                // Helper to wrap future code into a "try" block to catch
                // errors, if necessary.
                auto begin_try = [&](bool insert_try = true) -> std::optional<Builder::TryProxy> {
                    if ( ! (unit && insert_try) )
                        return {};

                    auto x = builder()->addTry();
                    pushBuilder(x.first);
                    return x.second;
                };

                // Helper to close previous "try" block and report
                // errors, if necessary.
                auto end_try = [&](std::optional<Builder::TryProxy>& try_) {
                    if ( ! try_ )
                        return;

                    popBuilder();

                    // We catch *any* exceptions here, not just parse
                    // errors, and not even only HILTI errors. The reason
                    // is that we want a reliable point of error handling
                    // no matter what kind of trouble a Spicy script runs
                    // into.
                    auto catch_ = try_->addCatch(builder()->parameter(HILTI_INTERNAL_ID("except"),
                                                                      builder()->typeName("hilti::SystemException")));

                    pushBuilder(std::move(catch_), [&]() {
                        pb->finalizeUnit(false, p.location());
                        run_finally();
                        builder()->addRethrow();
                    });
                };

                // First stage parse functionality implementing
                // initialization and potentially filtering.
                auto build_parse_stage1_logic = [&]() {
                    if ( unit ) {
                        auto* field = p.meta().field();
                        auto* type = p.type();

                        std::string msg;

                        if ( field && field->id() )
                            msg = field->id();

                        if ( type && unit->typeID() ) {
                            if ( msg.empty() )
                                msg = unit->typeID();
                            else
                                msg = fmt("%s: %s", msg, unit->typeID());
                        }

                        builder()->addDebugMsg("spicy", msg);
                        builder()->addCall("hilti::debugIndent", {builder()->stringLiteral("spicy")});
                    }

                    if ( unit ) {
                        auto pstate = state();
                        pstate.begin = builder()->addTmp("begin", builder()->begin(state().cur));
                        pushState(std::move(pstate));
                        pb->initializeUnit(p.location());
                    }
                };

                auto build_parse_stage1 = [&]() {
                    pushBuilder();

                    builder()->setLocation(p.location());

                    auto pstate = state();
                    pstate.self = builder()->expressionName(ID("self"));
                    pstate.data = builder()->id(HILTI_INTERNAL_ID("data"));
                    pstate.begin = builder()->id(HILTI_INTERNAL_ID("begin"));
                    pstate.cur = builder()->id(HILTI_INTERNAL_ID("cur"));
                    pstate.ncur = {};
                    pstate.trim = builder()->id(HILTI_INTERNAL_ID("trim"));
                    pstate.lahead = builder()->id(HILTI_INTERNAL_ID("lah"));
                    pstate.lahead_end = builder()->id(HILTI_INTERNAL_ID("lahe"));
                    pstate.error = builder()->id(HILTI_INTERNAL_ID("error"));

                    std::optional<PathTracker> path_tracker;
                    Expression* profiler = nullptr;

                    if ( unit->typeID() ) {
                        path_tracker = PathTracker(&path, unit->typeID());
                        auto* offset = builder()->memberCall(pstate.cur, "offset");
                        profiler =
                            builder()->startProfiler(fmt("spicy/unit/%s", hilti::util::join(path, "::")), offset);
                    }

                    QualifiedTypes x =
                        {builder()->qualifiedType(builder()->typeStreamView(), hilti::Constness::Mutable),
                         pb->lookAheadType(),
                         builder()->qualifiedType(builder()->typeStreamIterator(), hilti::Constness::Const),
                         builder()->qualifiedType(builder()->typeOptional(
                                                      builder()->qualifiedType(builder()->typeName(
                                                                                   "hilti::RecoverableFailure"),
                                                                               hilti::Constness::Const)),
                                                  hilti::Constness::Const)};
                    auto* result_type = builder()->typeTuple(x);
                    auto* store_result = builder()->addTmp("result", result_type, builder()->void_());

                    auto try_ = begin_try();

                    if ( unit )
                        pstate.unit = unit;

                    pushState(std::move(pstate));

                    // Disable trimming for random-access units.
                    pushBuilder(builder()->addIf(pb->featureConstant(unit, "uses_random_access")),
                                [&]() { builder()->addAssign(state().trim, builder()->bool_(false)); });

                    build_parse_stage1_logic();

                    // Call stage 2.
                    Expressions args = {state().data,   state().begin,      state().cur,  state().trim,
                                        state().lahead, state().lahead_end, state().error};

                    if ( addl_param )
                        args.push_back(builder()->id(addl_param->id()));

                    builder()->addLocal("filtered", builder()->strongReference(
                                                        builder()->qualifiedType(builder()->typeStream(),
                                                                                 hilti::Constness::Mutable)));

                    if ( unit ) {
                        pb->guardFeatureCode(unit, {"supports_filters"}, [&]() {
                            // If we have a filter attached, we initialize it and change to parse from its output.
                            auto* offset1 =
                                builder()->addTmp("offset1", builder()->memberCall(builder()->begin(
                                                                                       builder()->deref(state().data)),
                                                                                   "offset"));

                            auto* filtered =
                                builder()->assign(builder()->id("filtered"),
                                                  builder()->call("spicy_rt::filter_init",
                                                                  {state().self, state().data, state().cur}));

                            auto have_filter = builder()->addIf(filtered);
                            pushBuilder(std::move(have_filter));

                            auto args2 = args;

                            auto* filtered_data = builder()->addTmp(
                                "filtered_data",
                                builder()->qualifiedType(builder()->typeValueReference(
                                                             builder()->qualifiedType(builder()->typeStream(),
                                                                                      hilti::Constness::Mutable)),
                                                         hilti::Constness::Const),
                                builder()->id("filtered"));

                            args2[0] = filtered_data;
                            args2[1] = builder()->begin(builder()->deref(filtered_data));
                            args2[2] = builder()->deref(filtered_data);

                            builder()->addExpression(builder()->memberCall(state().self, id_stage2, args2));

                            auto* offset2 =
                                builder()->addTmp("offset2", builder()->memberCall(builder()->begin(
                                                                                       builder()->deref(state().data)),
                                                                                   "offset"));

                            auto* advance = builder()->difference(offset2, offset1);
                            pb->advanceInput(advance);

                            auto* result =
                                builder()->tuple({state().cur, state().lahead, state().lahead_end, state().error});

                            builder()->addAssign(store_result, result);
                            popBuilder();
                        });
                    }

                    auto not_have_filter = builder()->addIf(builder()->not_(builder()->id("filtered")));
                    pushBuilder(std::move(not_have_filter));
                    builder()->addAssign(store_result, builder()->memberCall(state().self, id_stage2, args));
                    popBuilder();

                    end_try(try_);
                    run_finally();

                    if ( profiler ) {
                        auto* offset =
                            builder()->memberCall(builder()->index(store_result, builder()->integer(0U)), "offset");
                        builder()->stopProfiler(profiler, offset);
                    }

                    popState();

                    builder()->addReturn(store_result);

                    return popBuilder()->block();
                }; // End of build_parse_stage1()

                // Second stage parse functionality implementing the main
                // part of the unit's parsing.
                auto build_parse_stage2_logic = [&]() {
                    if ( ! unit && p.meta().field() )
                        pushDestination(builder()->id(HILTI_INTERNAL_ID("dst")));
                    else
                        pushDestination(builder()->id("self"));

                    dispatch(p);

                    if ( unit ) {
                        builder()->addCall("hilti::debugDedent", {builder()->stringLiteral("spicy")});
                        popState();
                    }

                    auto* result = builder()->tuple({
                        state().cur,
                        state().lahead,
                        state().lahead_end,
                        state().error,
                    });

                    popDestination();
                    return result;
                };

                auto build_parse_stage12_or_stage2 = [&](bool join_stages) {
                    auto pstate = state();
                    pstate.self = builder()->expressionName(ID("self"));
                    pstate.data = builder()->id(HILTI_INTERNAL_ID("data"));
                    pstate.begin = builder()->id(HILTI_INTERNAL_ID("begin"));
                    pstate.cur = builder()->id(HILTI_INTERNAL_ID("cur"));
                    pstate.ncur = {};
                    pstate.trim = builder()->id(HILTI_INTERNAL_ID("trim"));
                    pstate.lahead = builder()->id(HILTI_INTERNAL_ID("lah"));
                    pstate.lahead_end = builder()->id(HILTI_INTERNAL_ID("lahe"));
                    pstate.error = builder()->id(HILTI_INTERNAL_ID("error"));

                    std::optional<PathTracker> path_tracker;

                    if ( unit ) {
                        pstate.unit = unit;

                        if ( unit->typeID() )
                            path_tracker = PathTracker(&path, unit->typeID());
                    }

                    pushState(std::move(pstate));
                    pushBuilder();

                    builder()->setLocation(p.location());

                    QualifiedTypes x =
                        {builder()->qualifiedType(builder()->typeStreamView(), hilti::Constness::Mutable),
                         pb->lookAheadType(),
                         builder()->qualifiedType(builder()->typeStreamIterator(), hilti::Constness::Const),
                         builder()->qualifiedType(builder()->typeOptional(
                                                      builder()->qualifiedType(builder()->typeName(
                                                                                   "hilti::RecoverableFailure"),
                                                                               hilti::Constness::Const)),
                                                  hilti::Constness::Const)};

                    auto* result_type = builder()->typeTuple(x);
                    auto* store_result = builder()->addTmp("result", result_type, builder()->void_());

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
                if ( unit ) {
                    addParseMethod(id_stage1.str() != HILTI_INTERNAL_ID("parse_stage1"), id_stage1,
                                   build_parse_stage1(), addl_param, p.location());
                    addParseMethod(true, id_stage2, build_parse_stage12_or_stage2(false), addl_param, p.location());
                }
                else
                    addParseMethod(id_stage1.str() != HILTI_INTERNAL_ID("parse_stage1"), id_stage1,
                                   build_parse_stage12_or_stage2(true), addl_param, p.location());

                return id_stage1;
            });

        Expressions args = {state().data,   state().begin,      state().cur,  state().trim,
                            state().lahead, state().lahead_end, state().error};

        if ( ! unit && p.meta().field() )
            args.push_back(destination());

        auto* call = builder()->memberCall(state().self, id, args);
        builder()->addAssign(builder()->tuple({state().cur, state().lahead, state().lahead_end, state().error}), call);
    }

    // Returns a boolean expression that's 'true' if a 'stop' was encountered.
    Expression* _parseProduction(const Production& p_, bool top_level, const production::Meta& meta) {
        const auto* p = &p_;
        const auto is_field_owner = (meta.field() && meta.isFieldProduction() && ! p->isA<production::Deferred>());

        auto* field = meta.field();
        assert(field || ! meta.isFieldProduction());

        HILTI_DEBUG(spicy::logging::debug::ParserBuilder, fmt("* production %s", hilti::util::trim(std::string(*p))));
        hilti::logging::DebugPushIndent _(spicy::logging::debug::ParserBuilder);

        if ( field ) {
            HILTI_DEBUG(spicy::logging::debug::ParserBuilder,
                        fmt("- field '%s': %s", field->id(), meta.field()->dump()));
        }

        if ( const auto& r = p->tryAs<production::Deferred>() )
            // Directly forward, without going through any of the remaining
            // machinery (but using the current meta).
            return _parseProduction(*grammar.resolved(r), top_level, meta);

        // Push destination for parsed value onto stack.

        Expression* need_copy_from = nullptr;

        if ( auto* c = meta.container() ) {
            pushTmpDestination("elem", c->parseType()->type()->elementType());
            pb->saveParsePosition(); // need to update position for container elements in case input is redirected
        }

        else if ( ! meta.isFieldProduction() )
            pushDestination(destination());

        else if ( field->parseType()->type()->isA<hilti::type::Void>() )
            // No value to store.
            pushDestination(builder()->void_());

        else if ( field->isForwarding() )
            // No need for a new destination but we need to initialize the one we have.
            builder()->addAssign(destination(true), builder()->default_(field->itemType()->type()));

        else if ( (field->isAnonymous() || field->isSkip()) &&
                  ! field->itemType()->type()->isA<hilti::type::Bitfield>() )
            // We won't have a field to store the value in, create a temporary.
            pushTmpDestination(fmt("transient_%s", field->id()), field->itemType());

        else if ( ! field->itemType()->type()->isMutable() ) {
            // For non-mutable types we use a temporary, rather than storing
            // directly into the struct field, to facilitate potential
            // optimizations. We cannot do that for mutable values because they
            // may be modified in-place during parsing, and we need to ensure
            // that any partial modifications are visible in the struct field.
            pushTmpDestination(fmt("v_%s", field->id()), field->itemType());
            need_copy_from = destination();
        }

        else {
            // Store parsed value directly in struct field.
            auto* dst = builder()->member(pb->state().self, field->id());
            pushDestination(dst);
        }

        // Parse production

        Expression* profiler = nullptr;
        std::optional<PathTracker> path_tracker;
        std::optional<std::pair<std::shared_ptr<Builder>, Builder::TryProxy>> try_;

        if ( is_field_owner ) {
            path_tracker = PathTracker(&path, field->id());
            auto* offset = builder()->memberCall(state().cur, "offset");
            profiler = builder()->startProfiler(fmt("spicy/unit/%s", hilti::util::join(path, "::")), offset);

            bool add_try = (! field->isAnonymous());
            for ( const auto* h : field->hooks() ) {
                if ( h->hookType() == declaration::hook::Type::Error ) {
                    add_try = true;
                    break;
                }
            }

            if ( add_try ) {
                // Wrap field parsing into try-block for per-field %error hook,
                // which may be attached directly or provided externally for
                // named fields.
                try_ = builder()->addTry();
                pushBuilder(try_->first);
            }
        }

        builder()->setLocation(p->location());

        Expression* pre_container_offset = nullptr;

        if ( is_field_owner )
            pre_container_offset = preParseField(*p, meta);

        beginProduction(*p);

        bool use_full_field_parsing = true;

        if ( is_field_owner && p->tryAs<production::Variable>() ) {
            // Try optimized field parsing first. If this works, we can skip
            // the full machinery below.
            if ( pb->parseType(p->type()->type(), p->meta(), destination(true), TypesMode::Optimize) )
                use_full_field_parsing = false; // parsed through optimized means
        }

        Expression* ncur = nullptr;
        Expression* ncur_max_size = nullptr;

        if ( use_full_field_parsing ) {
            Expression* length = nullptr;
            if ( is_field_owner )
                length = initFullFieldParsing(field);

            if ( const auto& x = p->tryAs<production::Enclosure>() )
                // Recurse.
                parseProduction(*x->child());

            else if ( p->isAtomic() )
                // dispatch() will write value to current destination.
                dispatch(p);

            else if ( const auto* unit = p->tryAs<production::Unit>(); unit && ! top_level ) {
                // Parsing a different unit type. We call the other unit's parse
                // function, but don't have to create it here.
                Expressions args = {pb->state().data,   pb->state().begin,      pb->state().cur,  pb->state().trim,
                                    pb->state().lahead, pb->state().lahead_end, pb->state().error};

                Location location;
                Expressions type_args;

                if ( meta.field() ) {
                    location = meta.field()->location();
                    type_args = meta.field()->arguments();
                }

                if ( meta.field() ) {
                    Expression* default_ = builder()->default_(builder()->typeName(unit->unitType()->typeID()),
                                                               type_args, std::move(location));
                    builder()->addAssign(destination(true), default_);
                }

                auto* call = builder()->memberCall(destination(), HILTI_INTERNAL_ID("parse_stage1"), args);
                builder()->addAssign(builder()->tuple({pb->state().cur, pb->state().lahead, pb->state().lahead_end,
                                                       pb->state().error}),
                                     call);
            }

            else if ( p->isA<production::Block>() )
                // No need to build this a full non-atomic production.
                dispatch(p);

            else if ( unit )
                parseNonAtomicProduction(*p, unit->unitType());

            else
                parseNonAtomicProduction(*p, {});

            if ( is_field_owner )
                std::tie(ncur, ncur_max_size) = finishFullFieldParsing(field, length);
        }

        endProduction(*p);

        if ( is_field_owner )
            postParseField(*p, meta, pre_container_offset, ncur, ncur_max_size, need_copy_from);

        if ( try_ ) {
            popBuilder(); // per-field try-block

            auto catch_ = try_->second.addCatch(
                builder()->parameter(HILTI_INTERNAL_ID("except"), builder()->typeName("hilti::SystemException")));

            pushBuilder(std::move(catch_), [&]() {
                auto* what = builder()->call("hilti::exception_what", {builder()->id(HILTI_INTERNAL_ID("except"))});
                builder()->addMemberCall(state().self, ID(fmt(HILTI_INTERNAL_ID("on_%s_error"), field->id().local())),
                                         {what}, field->meta());
                builder()->addRethrow();
            });
        }

        if ( is_field_owner ) {
            if ( profiler ) {
                auto* offset = builder()->memberCall(state().cur, "offset");
                builder()->stopProfiler(profiler, offset);
            }

            path_tracker.reset();
        }

        // Top of stack will now have the final value for the field.
        Expression* stop = builder()->bool_(false);

        if ( meta.container() ) {
            auto* elem = destination();
            popDestination();
            stop =
                pb->newContainerItem(field, meta.container(), destination(), elem, ! meta.container()->isTransient());
        }

        else if ( ! meta.isFieldProduction() )
            popDestination();

        else if ( field->parseType()->type()->isA<hilti::type::Void>() )
            popDestination();

        else if ( field->isForwarding() ) {
            // nothing to do
        }

        else if ( field->isAnonymous() )
            popDestination();

        else
            popDestination();

        pb->saveParsePosition();

        return stop;
    }

    Expression* preParseField(const Production& /* i */, const production::Meta& meta) {
        const auto& field = meta.field();
        assert(field); // Must only be called if we have a field.

        HILTI_DEBUG(spicy::logging::debug::ParserBuilder, fmt("- pre-parse field: %s", field->id()));

        // If the field holds a container we expect to see the offset of the field, not the individual container
        // elements inside e.g., this unit's fields hooks. Store the value before parsing of a container starts so we
        // can restore it later.
        Expression* pre_container_offset = nullptr;
        if ( field && field->isContainer() )
            pre_container_offset =
                builder()->addTmp("pre_container_offset",
                                  builder()->ternary(pb->featureConstant(state().unit, "uses_offset"),
                                                     builder()->member(state().self, HILTI_INTERNAL_ID("offset")),
                                                     builder()->integer(0)));

        if ( field && field->convertExpression() )
            // Need an additional temporary for the parsed field.
            pushTmpDestination(fmt("parsed_%s", field->id()), field->parseType());

        pb->enableDefaultNewValueForField(true);

        if ( field->attributes()->find(attribute::kind::Try) )
            pb->initBacktracking();

        if ( auto* c = field->condition() )
            pushBuilder(builder()->addIf(c));

        if ( field->originalType()->type()->isA<hilti::type::RegExp>() && ! field->isContainer() ) {
            bool needs_captures = true;

            if ( auto* ctor_ = field->ctor(); ctor_ && ctor_->as<hilti::ctor::RegExp>()->isNoSub() )
                needs_captures = false;

            if ( field->attributes()->find(hilti::attribute::kind::Nosub) )
                needs_captures = false;

            if ( needs_captures ) {
                auto pstate = state();
                pstate.captures = builder()->addTmp("captures", builder()->typeName("hilti::Captures"));
                pushState(std::move(pstate));
            }
        }

        if ( auto* a = field->attributes()->find(attribute::kind::ParseFrom) )
            redirectInputToBytesValue(pb->evaluateAttributeExpression(a, "parse_from"));

        if ( auto* a = field->attributes()->find(attribute::kind::ParseAt) )
            redirectInputToStreamPosition(pb->evaluateAttributeExpression(a, "parse_at"));

        if ( pb->options().getAuxOption<bool>("spicy.track_offsets", false) ) {
            auto* offsets = builder()->member(state().self, HILTI_INTERNAL_ID("offsets"));
            auto* cur_offset = builder()->memberCall(state().cur, "offset");

            // _offsets[field] = (self.offset(), null);
            builder()->addAssign(builder()->index(offsets, builder()->string(field->id(), false)),
                                 builder()->tuple({cur_offset, builder()->null()}));
        }

        return pre_container_offset;
    }

    // Sets up parsing infrastructure for non-optimized fields and returns the
    // expression used for size or max size.
    Expression* initFullFieldParsing(type::unit::item::Field* field) {
        // `&size` and `&max-size` share the same underlying infrastructure
        // so try to extract both of them and compute the ultimate value.
        Expression* length = nullptr;
        // Only at most one of `&max-size` and `&size` will be set.
        assert(! (field->attributes()->find(attribute::kind::Size) &&
                  field->attributes()->find(attribute::kind::MaxSize)));
        if ( auto* a = field->attributes()->find(attribute::kind::Size) )
            length = pb->evaluateAttributeExpression(a, "size");
        if ( auto* a = field->attributes()->find(attribute::kind::MaxSize) )
            // Append a sentinel byte for `&max-size` so we can detect reads beyond the expected length.
            length = builder()->addTmp("max_size_with_sentinel", builder()->typeUnsignedInteger(64),
                                       builder()->sum(pb->evaluateAttributeExpression(a, "max_size"),
                                                      builder()->integer(1U)));

        if ( length ) {
            // Limit input to the specified length.
            auto* limited = builder()->addTmp("limited_", builder()->memberCall(state().cur, "limit", {length}));

            // Establish limited view, remembering position to continue at.
            auto pstate = state();
            pstate.cur = limited;
            pstate.ncur = builder()->addTmp("ncur", builder()->memberCall(state().cur, "advance", {length}));
            pushState(std::move(pstate));
        }
        else {
            auto pstate = state();
            pstate.ncur = {};
            pushState(std::move(pstate));
        }

        return length;
    }

    // Tears down parsing infrastructure for non-optimized fields.
    //
    // Returns two expressions:
    // 1. `cur` from the state that was current when calling the method.
    // 2. `ncur_max_size` if we're parsing with `&max-size`, which in that case
    // is the position in the limited view we ended parsing to; this will be
    // used to compute how much data we consumed from the original view.
    std::pair<Expression*, Expression*> finishFullFieldParsing(type::unit::item::Field* field, Expression* length) {
        std::pair<Expression*, Expression*> result = {state().ncur, {}};

        if ( auto* a = field->attributes()->find(attribute::kind::MaxSize) ) {
            assert(state().ncur);
            // Check that we did not read into the sentinel byte.
            auto* cond = builder()->greaterEqual(builder()->memberCall(state().cur, "offset"),
                                                 builder()->memberCall(state().ncur, "offset"));
            auto exceeded = builder()->addIf(cond);
            pushBuilder(std::move(exceeded), [&]() {
                // We didn't finish parsing the data, which is an error.
                if ( ! field->isAnonymous() && ! field->isSkip() )
                    // Clear the field in case the type parsing has started to fill it.
                    builder()->addExpression(builder()->unset(state().self, field->id()));

                pb->parseError("parsing not done within &max-size bytes", a->meta());
            });

            result.second = state().cur;
        }

        else if ( auto* a = field->attributes()->find(attribute::kind::Size);
                  a && ! field->attributes()->find(attribute::kind::Eod) ) {
            assert(state().ncur);
            assert(length);
            _checkSizeAmount(length, a->meta(), state().ncur, field);
        }

        popState(); // from &size (pushed even if absent)
        return result;
    }

    /**
     * Advances a view by the amount consumed in the provided limited view, which may not be
     * fully consumed. The limited view must point into the `cur` stream.
     */
    Expression* advanceLimited(Expression* cur, Expression* limited) {
        // Compute the difference in offset; this is safe since the limited view is into the
        // original stream `cur` points to.
        return builder()->memberCall(cur, "advance",
                                     {builder()->difference(builder()->memberCall(limited, "offset"),
                                                            builder()->memberCall(cur, "offset"))});
    }


    void postParseField(const Production& p, const production::Meta& meta, Expression* pre_container_offset,
                        Expression* ncur, Expression* ncur_max_size, Expression* need_copy_from) {
        const auto& field = meta.field();
        assert(field); // Must only be called if we have a field.

        // If the field holds a container we expect to see the offset of the field, not the individual container
        // elements inside e.g., this unit's fields hooks. Temporarily restore the previously stored offset.
        Expression* prev = nullptr;
        if ( pre_container_offset ) {
            prev = builder()->addTmp("prev",
                                     builder()->ternary(pb->featureConstant(state().unit, "uses_offset"),
                                                        builder()->member(state().self, HILTI_INTERNAL_ID("offset")),
                                                        builder()->integer(0)));

            pb->guardFeatureCode(state().unit, {"uses_offset"}, [&]() {
                builder()->addAssign(builder()->member(state().self, HILTI_INTERNAL_ID("offset")),
                                     pre_container_offset);
            });
        }

        HILTI_DEBUG(spicy::logging::debug::ParserBuilder, fmt("- post-parse field: %s", field->id()));

        if ( pb->options().getAuxOption<bool>("spicy.track_offsets", false) ) {
            assert(field->index());

            // _offsets[field] = (offsets[field].begin(), self.offset());
            auto* offsets = builder()->member(state().self, HILTI_INTERNAL_ID("offsets"));
            auto* begin = builder()->index(builder()->index(offsets, builder()->string(field->id(), false)),
                                           builder()->integer(0U));
            auto* end = builder()->memberCall(state().cur, "offset");
            builder()->addAssign(builder()->index(offsets, builder()->string(field->id(), false)),
                                 builder()->tuple({begin, end}));
        }

        auto* val = destination();

        if ( field->convertExpression() ) {
            // Value was stored in temporary. Apply expression and store result
            // at destination.
            popDestination();
            pb->applyConvertExpression(*field, val, destination(true));
        }

        if ( field->attributes()->find(attribute::kind::ParseFrom) ||
             field->attributes()->find(attribute::kind::ParseAt) ) {
            ncur = {};
            popState();
            pb->saveParsePosition();
        }

        else if ( ncur_max_size )
            ncur = advanceLimited(state().cur, ncur_max_size);

        if ( ncur )
            builder()->addAssign(state().cur, ncur);

        if ( need_copy_from ) {
            // Copy parsed value from temporary into user-visible struct field.
            auto* dst = builder()->member(state().self, field->id());
            builder()->addAssign(dst, need_copy_from);
        }

        if ( ! meta.container() ) {
            if ( pb->isEnabledDefaultNewValueForField() && state().literal_mode == LiteralMode::Default )
                pb->newValueForField(meta, destination(), val);
        }

        if ( state().captures )
            popState();

        if ( prev )
            pb->guardFeatureCode(state().unit, {"uses_offset"}, [&]() {
                builder()->addAssign(builder()->member(state().self, HILTI_INTERNAL_ID("offset")), prev);
            });

        if ( field->condition() )
            popBuilder();

        if ( field->attributes()->find(attribute::kind::Try) )
            pb->finishBacktracking();
    }

    // top_level: true if we're called directly for the grammar's root unit, and
    // don't need to create a function wrapper first.
    //
    // Returns a boolean expression that's 'true' if a 'stop' was encountered.
    Expression* parseProduction(const Production& p, bool top_level = false) {
        return _parseProduction(p, top_level, p.meta());
    }

    // Inject parser code to skip a certain regexp pattern in the input. We
    // expect the passed expression to contain a ctor for a RegExp; else this
    // function does nothing.
    void skipRegExp(Expression* e) {
        hilti::ctor::RegExp* c = nullptr;

        if ( auto* ctor = e->tryAs<hilti::expression::Ctor>() )
            c = ctor->ctor()->tryAs<hilti::ctor::RegExp>();

        if ( ! c )
            return;

        // Store the regexp as a global constant to avoid recomputing the
        // regexp on each runtime pass through the calling context.
        auto* re = pb->cg()->addGlobalConstant(builder()->ctorRegExp(c->patterns()));

        auto* ncur = builder()->addTmp("ncur", state().cur);
        auto* ms = builder()->local("ms", builder()->memberCall(re, "token_matcher"));
        auto body = builder()->addWhile(ms, builder()->bool_(true));
        pushBuilder(std::move(body));

        auto* rc = builder()->addTmp("rc", builder()->typeSignedInteger(32));
        builder()->addAssign(builder()->tuple({rc, ncur}),
                             builder()->memberCall(builder()->id("ms"), "advance", {ncur}), c->meta());

        auto switch_ = builder()->addSwitch(rc, c->meta());

        // Match possible with additional data, continue matching.
        auto no_match_try_again = switch_.addCase(builder()->integer(-1));
        pushBuilder(std::move(no_match_try_again));
        auto pstate = pb->state();
        pstate.cur = ncur;
        pb->pushState(std::move(pstate));
        builder()->addExpression(pb->waitForInputOrEod());
        pb->popState();
        builder()->addContinue();
        popBuilder();

        // No match found, leave `cur` unchanged.
        auto no_match = switch_.addCase(builder()->integer(0));
        pushBuilder(std::move(no_match));
        builder()->addBreak();
        popBuilder();

        // Match found, update `cur`.
        auto match = switch_.addDefault();
        pushBuilder(std::move(match));
        builder()->addAssign(state().cur, ncur);
        pb->trimInput();
        builder()->addBreak();
        popBuilder();

        popBuilder();
    };

    // Retrieve a look-ahead symbol. Once the code generated by the function
    // has executed, the parsing state will reflect what look-ahead has been
    // found, including `EOD` if `cur` is the end-of-data, and `None` if no
    // expected look-ahead token is found.
    void getLookAhead(const production::LookAhead& lp) {
        const auto& [lah1, lah2] = lp.lookAheads();
        auto productions = hilti::util::setUnion(lah1, lah2);
        getLookAhead(productions, lp.symbol(), lp.location());
    }

    void getLookAhead(const production::Set& tokens, const std::string& symbol, const Location& location,
                      LiteralMode mode = LiteralMode::Try) {
        assert(mode != LiteralMode::Default);

        // If we're at EOD, return that directly.
        auto [true_, false_] = builder()->addIfElse(pb->atEod());
        true_->addAssign(state().lahead, builder()->integer(look_ahead::Eod));

        pushBuilder(std::move(false_));

        // Collect all expected terminals.
        auto regexps = std::vector<Production*>();
        auto other = std::vector<Production*>();
        std::ranges::partition_copy(tokens, std::back_inserter(regexps), std::back_inserter(other),
                                    [](auto& p) { return p->type()->type()->template isA<hilti::type::RegExp>(); });

        auto parse = [&]() {
            bool first_token = true;

            // Construct a `try`/`catch` block to guard code in
            // `LiteralMode::Search` against `MissingData` errors.
            //
            // The passed callback will be invoked after a `MissingData` was
            // encountered and recovered from.
            //
            // Returns a pointer to the constructed builder if any was constructed.
            auto guard_search = [&](auto&& cb) {
                if ( mode != LiteralMode::Search )
                    return std::shared_ptr<Builder>();

                auto [body, try_] = builder()->addTry();

                pushBuilder(try_.addCatch(builder()->parameter(ID("e"), builder()->typeName("hilti::MissingData"))),
                            [&]() {
                                // `advance` has failed, retry at the next non-gap block.
                                pb->advanceToNextData();

                                cb();

                                // Continue incremental matching.
                                builder()->addContinue();
                            });

                return pushBuilder(std::move(body));
            };

            // Parse regexps in parallel.
            if ( ! regexps.empty() ) {
                first_token = false;

                // Create the joint regular expression. The token IDs become the regexps' IDs.
                auto patterns = regexps | std::views::transform([](const auto& c) {
                                    return std::make_pair(c->template as<production::Ctor>()
                                                              ->ctor()
                                                              ->template as<hilti::ctor::RegExp>()
                                                              ->patterns(),
                                                          c->tokenID());
                                });

                auto flattened = hilti::ctor::regexp::Patterns();

                for ( const auto& p : patterns ) {
                    for ( const auto& r : p.first )
                        flattened.emplace_back(r.value(), r.isCaseInsensitive(), p.second);
                }

                auto* re = pb->cg()->addGlobalConstant(
                    builder()->ctorRegExp(std::move(flattened), builder()->attributeSet({builder()->attribute(
                                                                    hilti::attribute::kind::Nosub)})));
                // Create the token matcher state.
                builder()->addLocal(ID("ncur"), state().cur);
                auto* ms = builder()->local("ms", builder()->memberCall(re, "token_matcher"));

                // Create loop for incremental matching.
                pushBuilder(builder()->addWhile(ms, builder()->bool_(true)), [&]() {
                    builder()->addLocal(ID("rc"), builder()->qualifiedType(builder()->typeSignedInteger(32),
                                                                           hilti::Constness::Const));

                    auto guarded_search = guard_search([&]() {
                        // We operate on `ncur` while `advanceToNextData`
                        // updates `cur`; copy its result over.
                        builder()->addAssign(ID("ncur"), state().cur);
                    });

                    // Potentially bracketed `advance`.
                    builder()->addAssign(builder()->tuple({builder()->id("rc"), builder()->id("ncur")}),
                                         builder()->memberCall(builder()->id("ms"), "advance", {builder()->id("ncur")}),
                                         location);

                    if ( guarded_search )
                        popBuilder();

                    auto switch_ = builder()->addSwitch(builder()->id("rc"), location);

                    // No match, try again.
                    pushBuilder(switch_.addCase(builder()->integer(-1)), [&]() {
                        auto ok = builder()->addIf(pb->waitForInputOrEod());
                        ok->addContinue();
                        builder()->addAssign(state().lahead, builder()->integer(look_ahead::Eod));
                        builder()->addAssign(state().lahead_end, builder()->begin(state().cur));
                        builder()->addBreak();
                    });

                    // No match, error.
                    pushBuilder(switch_.addCase(builder()->integer(0)), [&]() {
                        pb->state().printDebug(builder());
                        builder()->addAssign(state().lahead, builder()->integer(look_ahead::None));
                        builder()->addAssign(state().lahead_end, builder()->begin(state().cur));
                        builder()->addBreak();
                    });

                    pushBuilder(switch_.addDefault(), [&]() {
                        builder()->addAssign(state().lahead, builder()->id("rc"));
                        builder()->addAssign(state().lahead_end, builder()->begin(builder()->id("ncur")));
                        builder()->addBreak();
                    });
                });

                pb->state().printDebug(builder());
            }

            // Parse non-regexps successively.
            for ( auto& p : other ) {
                if ( ! p->isLiteral() )
                    continue;

                auto pstate = pb->state();
                pstate.literal_mode = mode;
                pushState(std::move(pstate));

                auto guarded_search = guard_search([]() {});

                auto* match = builder()->addTmp("literal", pb->parseLiteral(*p, {}));

                popState();

                if ( first_token ) {
                    // Simplified version, no previous match possible that we
                    // would need to compare against.
                    first_token = false;
                    auto true_ = builder()->addIf(builder()->unequal(match, builder()->begin(state().cur)));
                    true_->addAssign(state().lahead, builder()->integer(p->tokenID()));
                    true_->addAssign(state().lahead_end, match);
                }
                else {
                    // If the length is larger than any token we have found so
                    // far, we take it. If length is the same as previous one,
                    // it's ambiguous and we bail out.
                    auto true_ = builder()->addIf(builder()->local("i", match),
                                                  builder()->and_(builder()->unequal(builder()->id("i"),
                                                                                     builder()->begin(state().cur)),
                                                                  builder()->greaterEqual(builder()->id("i"),
                                                                                          state().lahead_end)));

                    auto ambiguous = true_->addIf(
                        builder()->and_(builder()->unequal(state().lahead, builder()->integer(look_ahead::None)),
                                        builder()->equal(builder()->id("i"), state().lahead_end)));
                    pushBuilder(std::move(ambiguous));
                    pb->parseError("ambiguous look-ahead token match", location);
                    popBuilder();

                    true_->addAssign(state().lahead, builder()->integer(p->tokenID()));
                    true_->addAssign(state().lahead_end, builder()->id("i"));
                }

                if ( guarded_search )
                    popBuilder();

                pb->state().printDebug(builder());
            };
        };

        switch ( mode ) {
            case LiteralMode::Default:
            case LiteralMode::Try:
            case LiteralMode::Skip: {
                parse();
                break;
            }

            case LiteralMode::Search: {
                // Create a loop for search mode.
                pushBuilder(builder()->addWhile(builder()->bool_(true)), [&]() {
                    parse();

                    auto [if_, else_] = builder()->addIfElse(builder()->or_(pb->atEod(), state().lahead));
                    pushBuilder(std::move(if_), [&]() { builder()->addBreak(); });
                    pushBuilder(std::move(else_), [&]() { pb->advanceToNextData(); });
                });

                break;
            }
        }

        popBuilder();
    }

    // Generate code to synchronize on the given production. We assume that the
    // given production supports some form of lookahead; if the production is
    // not supported an error will be generated.
    void syncProduction(const Production& p_) {
        const auto* p = &p_;

        if ( const auto* resolved = p->tryAs<production::Deferred>() ) {
            p = grammar.resolved(resolved);
        }

        // Validation.
        const auto* while_ = p->tryAs<production::While>();
        if ( while_ && while_->expression() )
            hilti::logger().error("&synchronize cannot be used on while loops with conditions");

        Expression* profiler = nullptr;

        // Helper to validate the parser state after search for a lookahead.
        auto validate_search_result = [&]() {
            if ( profiler ) {
                auto* offset = builder()->memberCall(state().cur, "offset");
                builder()->stopProfiler(profiler, offset);
            }

            pushBuilder(builder()->addIf(builder()->or_(pb->atEod(), builder()->not_(state().lahead))), [&]() {
                // We land here if we failed to find successfully find any sync
                // token in the input stream, or because we ran into EOD. We cannot
                // recover from this and directly trigger a parse error.
                builder()->addAssert(state().error, "original error not set");
                auto* original_error = builder()->deref(state().error);
                pb->parseError("failed to synchronize: %s", original_error);
            });
        };

        // Handle synchronization via `synchronize-at` or `synchronize-after` unit properties.
        // We can either see a unit for synchronization in a list (generating a
        // `while` production), or directly.
        type::Unit* unit_type = nullptr;
        if ( while_ ) {
            if ( const auto& field = while_->meta().field() )
                if ( auto* unit = field->parseType()->type()->elementType()->type()->tryAs<type::Unit>() )
                    unit_type = unit;
        }

        else if ( const auto& unit = p->tryAs<production::Unit>() )
            unit_type = unit->unitType();

        auto* offset = builder()->memberCall(state().cur, "offset");

        profiler = builder()->startProfiler(hilti::util::fmt("spicy/unit/%s/" HILTI_INTERNAL_ID("synchronize"),
                                                             state().unit_id),
                                            offset);

        if ( unit_type ) {
            auto* const synchronize_at = unit_type->propertyItem("%synchronize-at");
            auto* const synchronize_after = unit_type->propertyItem("%synchronize-after");

            Expression* e = nullptr;

            if ( synchronize_at )
                e = synchronize_at->expression();

            if ( synchronize_after )
                e = synchronize_after->expression();

            if ( e ) {
                const auto id = cg()->uniquer()->get("synchronize");
                auto* const ctor_ = e->tryAs<hilti::expression::Ctor>();
                assert(ctor_);
                auto ctor = std::make_unique<production::Ctor>(context(), cg()->uniquer()->get(id), ctor_->ctor(),
                                                               ctor_->meta().location());

                // We might use a different look-ahead for synchronization that
                // for regular parsing at this position, e.g., due to
                // `%synchronize-[at|after]`, so temporarily set a new value.
                auto pstate = state();
                pstate.lahead = builder()->addTmp("sync_lahead", builder()->id(HILTI_INTERNAL_ID("lah")));
                pushState(std::move(pstate));

                getLookAhead({ctor.get()}, id, ctor->location(), LiteralMode::Search);
                validate_search_result();

                if ( synchronize_after )
                    pb->consumeLookAhead();

                popState(); // Look-ahead for synchronization.

                return;
            }
        }

        auto tokens = grammar.lookAheadsForProduction(p);
        if ( ! tokens || tokens->empty() ) {
            // ignore error message that was returned, it's a bit cryptic for our use-case here
            hilti::logger().error("&synchronize cannot be used on field, no look-ahead tokens found", p->location());
            return;
        }

        for ( const auto& p : *tokens ) {
            if ( ! p->isLiteral() ) {
                hilti::logger().error("&synchronize cannot be used on field, look-ahead contains non-literals",
                                      p->location());
                return;
            }
        }

        state().printDebug(builder());

        getLookAhead(*tokens, p->symbol(), p->location(), LiteralMode::Search);
        validate_search_result();
    }

    // Generate code to synchronize on the given production always advancing input.
    // This function behaves like `syncProduction`, but makes sure that in case
    // the current input already appears to be synchronized we find a new
    // position in the input which is synchronized.
    void syncProductionNext(const Production& p) {
        // We wrap lookahead search in a loop so we can advance manually should it get stuck
        // at the same input position. This can happen if we end up synchronizing on an
        // input token which matches something near the start of the list element type, but
        // is followed by other unexpected data. Without loop we would end up
        // resynchronizing at the same input position again.
        auto* search_start = builder()->local("search_start", state().cur);
        pushBuilder(builder()->addWhile(search_start, builder()->bool_(true)), [&]() {
            // Generate code which synchronizes the input. This will throw a parse error
            // if we hit EOD which will implicitly break from the loop.

            // Call any `%sync_advance` hook as we enter sync mode.
            pb->syncAdvanceHook();

            // The current input has failed, either since it does not match or since
            // data was missing. Advance the input to go to the next data.
            pb->advanceToNextData();
            syncProduction(p);

            pushBuilder(builder()->addIf(builder()->equal(builder()->id("search_start"), state().cur)), [&]() {
                builder()->addDebugMsg("spicy",
                                       "search for sync token did not advance "
                                       "input, advancing explicitly");
                pb->advanceToNextData();
                builder()->addContinue();
            });

            pb->beforeHook();
            builder()->addDebugMsg("spicy-verbose", "successfully synchronized");
            builder()->addMemberCall(state().self, HILTI_INTERNAL_ID("on_0x25_synced"), {}, p.location());
            pb->afterHook();

            // Sync point found, break from loop.
            builder()->addBreak();
        });
    }

    // Adds a method, and its implementation, to the current parsing struct
    // type that has the standard signature for parse methods.
    void addParseMethod(bool add_decl, const ID& id, hilti::statement::Block* body,
                        hilti::type::function::Parameter* addl_param = {}, const Meta& m = {}) {
        auto qualified_id = pb->state().unit_id + id;
        auto* ftype = pb->parseMethodFunctionType(addl_param, m);
        auto* func = builder()->function(qualified_id, ftype, body, {}, m);
        auto* decl = builder()->declarationFunction(func, hilti::declaration::Linkage::Struct, m);

        if ( add_decl )
            new_fields.emplace_back(builder()->declarationField(id, ftype, nullptr));

        cg()->addDeclaration(decl);
    }

    // Redirects input to be read from given bytes value next.
    // This function pushes a new parser state which should be popped later.
    void redirectInputToBytesValue(Expression* value) {
        auto pstate = state();
        pstate.trim = builder()->bool_(false);
        pstate.lahead = builder()->addTmp("parse_lah", pb->lookAheadType(), builder()->integer(look_ahead::None));
        pstate.lahead_end = builder()->addTmp("parse_lahe", builder()->typeStreamIterator());

        auto* tmp = builder()->addTmp("parse_from",
                                      builder()->typeValueReference(
                                          builder()->qualifiedType(builder()->typeStream(), hilti::Constness::Mutable)),
                                      value);
        builder()->addMemberCall(tmp, "freeze", {});

        pstate.data = tmp;
        pstate.begin = builder()->addTmp("parse_begin", builder()->begin(builder()->deref(tmp)));
        pstate.cur = builder()->addTmp("parse_cur", builder()->typeStreamView(), builder()->deref(tmp));
        pstate.ncur = {};
        pushState(std::move(pstate));
    }

    // Redirects input to be read from given stream position next.
    // This function pushes a new parser state which should be popped later.
    void redirectInputToStreamPosition(Expression* position) {
        auto pstate = state();
        pstate.trim = builder()->bool_(false);
        pstate.lahead = builder()->addTmp("parse_lah", pb->lookAheadType(), builder()->integer(look_ahead::None));
        pstate.lahead_end = builder()->addTmp("parse_lahe", builder()->typeStreamIterator());

        pstate.begin = builder()->addTmp("parse_begin", position);
        auto* cur = builder()->memberCall(state().cur, "advance", {pstate.begin});
        pstate.cur = builder()->addTmp("parse_cur", cur);
        pstate.ncur = {};
        pushState(std::move(pstate));
    }

    // Start sync and trial mode.
    void startSynchronize(const Production& sync) {
        builder()->addComment("Wrap remaining fields in loop so we can resynchronize on failure during trial mode");

        // This pushes the while loop body onto the builder so the parsing code
        // for all subsequent fields is executed in this loop. For that reason
        // the loop bpdy needs to execute at least one time.
        auto while_ = builder()->addWhile(builder()->bool_(true));
        pushBuilder(std::move(while_));

        // Variable storing whether we actually entered trial mode.
        auto* is_trial_mode = builder()->addTmp("is_trial_mode", builder()->bool_(false));

        pushBuilder(builder()->addIf(state().error), [&]() {
            builder()->addComment("Synchronize input");

            // Call any `%sync_advance` hook as we enter sync mode.
            pb->syncAdvanceHook();

            syncProduction(sync);

            builder()->addAssign(is_trial_mode, builder()->bool_(true));

            pb->beforeHook();
            builder()->addDebugMsg("spicy-verbose", "successfully synchronized");
            builder()->addMemberCall(state().self, HILTI_INTERNAL_ID("on_0x25_synced"), {}, sync.location());
            pb->afterHook();
        });

        auto [body, try_] = builder()->addTry();
        pushBuilder(try_.addCatch(builder()->parameter(ID("e"), builder()->typeName("hilti::RecoverableFailure"))),
                    [&]() {
                        pushBuilder(builder()->addIf(
                                        builder()->or_(builder()->not_(is_trial_mode), builder()->not_(state().error))),
                                    [&]() { builder()->addRethrow(); });

                        builder()->addDebugMsg("spicy", "parse error during trial mode, resynchronizing: %s",
                                               {builder()->id("e")});

                        // Advance input so we can find the next synchronization point.
                        pb->advanceToNextData();

                        builder()->addContinue();
                    });

        pushBuilder(std::move(body));
    }

    /** End sync and trial mode. */
    void finishSynchronize() {
        builder()->addBreak();
        popBuilder(); // body.
        popBuilder(); // while_.
    }

    std::pair<Expression*, Expression*> preAggregate(const Production* p, AttributeSet* attributes) {
        Expression* length = nullptr;
        builder()->addCall("hilti::debugIndent", {builder()->stringLiteral("spicy")});

        if ( const auto& a = attributes->find(attribute::kind::ParseFrom) )
            redirectInputToBytesValue(pb->evaluateAttributeExpression(a, "parse_from"));

        if ( auto* a = attributes->find(attribute::kind::ParseAt) )
            redirectInputToStreamPosition(pb->evaluateAttributeExpression(a, "parse_at"));

        Expression* ncur = nullptr;
        if ( const auto& a = attributes->find(attribute::kind::Size) ) {
            // Limit input to the specified length.
            length = pb->evaluateAttributeExpression(a, "size");
            auto* limited = builder()->addTmp("limited_field", builder()->memberCall(state().cur, "limit", {length}));

            // Establish limited view, remembering position to continue at.
            auto pstate = state();
            pstate.cur = limited;
            // NOTE: We do not store `ncur` in `pstate` since field code
            // might update `pstate.ncur` as well.
            ncur = builder()->addTmp("ncur", builder()->memberCall(state().cur, "advance", {length}));
            pushState(std::move(pstate));
        }

        return {ncur, length};
    }

    void postAggregate(const Production* p, AttributeSet* attributes, Expression* ncur, Expression* length) {
        if ( auto* a = attributes->find(attribute::kind::Size); a && ! attributes->find(attribute::kind::Eod) ) {
            assert(length);
            _checkSizeAmount(length, a->meta(), ncur);
            popState();
            builder()->addAssign(state().cur, ncur);
        }

        if ( attributes->find(attribute::kind::ParseFrom) || attributes->find(attribute::kind::ParseAt) )
            popState();

        builder()->addCall("hilti::debugDedent", {builder()->stringLiteral("spicy")});
    }

    void operator()(const production::Block* p) final {
        auto build_block_productions = [this, p](const auto& productions) {
            auto [ncur, length] = preAggregate(p, p->attributes());

            for ( const auto& i : productions )
                parseProduction(*i);

            postAggregate(p, p->attributes(), ncur, length);
        };

        std::optional<std::pair<BuilderPtr, BuilderPtr>> if_else;

        if ( auto* condition = p->condition() ) {
            if_else = builder()->addIfElse(condition);
            pushBuilder(if_else->first);
        }

        build_block_productions(p->productions());

        if ( if_else ) {
            popBuilder();

            if ( const auto& else_ = p->elseProductions(); else_.size() ) {
                pushBuilder(if_else->second);
                build_block_productions(p->elseProductions());
                popBuilder();
            }
        }
    }

    void operator()(const production::Epsilon* /* p */) final {}

    void operator()(const production::Counter* p) final {
        auto* repeat = p->expression();

        // Fields with stored elements should reserve the amount they will parse
        if ( auto* field = p->meta().field(); field && ! field->isTransient() ) {
            // Create a temporary so stateful size expressions are only evaluated once.
            auto* uint64 = builder()->qualifiedType(builder()->typeUnsignedInteger(64), hilti::Constness::Const);
            repeat = builder()->addTmp("repeat", uint64, repeat);

            // Cap the number of reserved elements to avoid allocating
            // excessive memory. The vector parsing might be stopped with
            // `stop` in which case we would not store the declared repeat
            // count anyway.
            auto* max_reserve = builder()->integer(128U);
            auto* num_elements = builder()->min(max_reserve, repeat);

            builder()->addExpression(builder()->memberCall(destination(), "reserve", {num_elements}));
        }

        auto body = builder()->addWhile(builder()->local(HILTI_INTERNAL_ID("i"),
                                                         builder()->qualifiedType(builder()->typeUnsignedInteger(64),
                                                                                  hilti::Constness::Mutable),
                                                         repeat),
                                        builder()->id(HILTI_INTERNAL_ID("i")));

        pushBuilder(body);
        body->addExpression(builder()->decrementPostfix(builder()->id(HILTI_INTERNAL_ID("i"))));

        auto parse = [&]() {
            auto* stop = parseProduction(*p->body());
            auto b = builder()->addIf(stop);
            b->addBreak();
        };

        // The container element type creating this counter was marked `&synchronize`. Allow any container
        // element to fail parsing and be skipped. This means that if `n` elements where requested and one
        // element fails to parse, we will return `n-1` elements.
        if ( auto* f = p->body()->meta().field(); f && f->attributes()->find(attribute::kind::Synchronize) ) {
            auto try_ = builder()->addTry();
            pushBuilder(try_.first, [&]() { parse(); });

            pushBuilder(try_.second.addCatch(
                            builder()->parameter(ID("e"), builder()->typeName("hilti::RecoverableFailure"))),
                        [&]() {
                            // Remember the original error so we can report it in case the sync failed.
                            builder()->addAssign(state().error, builder()->id("e"));

                            builder()->addDebugMsg("spicy-verbose",
                                                   "failed to parse list element, will try to "
                                                   "synchronize at next possible element");

                            syncProductionNext(*p);
                        });
        }

        else
            parse();

        popBuilder();
    }

    void operator()(const production::Enclosure* p) final {
        builder()->addCall("hilti::debugIndent", {builder()->stringLiteral("spicy")});
        parseProduction(*p->child());
        builder()->addCall("hilti::debugDedent", {builder()->stringLiteral("spicy")});
    }

    void operator()(const production::ForEach* p) final {
        Expression* cond = nullptr;

        if ( p->isEodOk() )
            cond = builder()->not_(pb->atEod());
        else
            cond = builder()->bool_(true);

        auto body = builder()->addWhile(cond);
        pushBuilder(std::move(body));
        auto* cookie = pb->initLoopBody();
        auto* stop = parseProduction(*p->body());
        auto b = builder()->addIf(stop);
        b->addBreak();
        pb->finishLoopBody(cookie, p->location());
        popBuilder();
    }

    void operator()(const production::Deferred* p) final {
        abort();
        auto* x = grammar.resolved(p);
        parseProduction(*x);
    }

    void operator()(const production::Switch* p) final {
        if ( auto* condition = p->condition() )
            pushBuilder(builder()->addIf(condition));

        auto [ncur, length] = preAggregate(p, p->attributes());

        auto switch_ = builder()->addSwitch(p->expression(), p->location());

        for ( const auto& [exprs, prod] : p->cases() ) {
            auto case_ = switch_.addCase(exprs, prod->location());
            pushBuilder(std::move(case_), [&, &prod = prod]() { parseProduction(*prod); });
        }

        if ( const auto* prod = p->default_() ) {
            auto default_ = switch_.addDefault(prod->location());
            pushBuilder(std::move(default_), [&]() { parseProduction(*prod); });
        }
        else {
            auto default_ = switch_.addDefault(p->location());
            pushBuilder(std::move(default_), [&]() {
                pb->parseError("no matching case in switch statement for value '%s'", {p->expression()}, p->location());
            });
        }

        postAggregate(p, p->attributes(), ncur, length);

        if ( p->condition() )
            popBuilder();
    }

    void operator()(const production::Unit* p) final {
        auto pstate = pb->state();
        pstate.self = destination();
        pushState(std::move(pstate));

        // `&size` and `&max-size` share the same underlying infrastructure
        // so try to extract both of them and compute the ultimate value. We
        // already reject cases where `&size` and `&max-size` are combined
        // during validation.
        Expression* length = nullptr;
        // Only at most one of `&max-size` and `&size` will be set.
        assert(! (p->unitType()->attributes()->find(attribute::kind::Size) &&
                  p->unitType()->attributes()->find(attribute::kind::MaxSize)));
        if ( auto* a = p->unitType()->attributes()->find(attribute::kind::Size) )
            length = pb->evaluateAttributeExpression(a, "size");
        else if ( auto* a = p->unitType()->attributes()->find(attribute::kind::MaxSize) )
            // Append a sentinel byte for `&max-size` so we can detect reads beyond the expected length.
            length = builder()->addTmp("max_size_with_sentinel", builder()->typeUnsignedInteger(64),
                                       builder()->sum(pb->evaluateAttributeExpression(a, "max_size"),
                                                      builder()->integer(1U)));

        if ( length ) {
            // Limit input to the specified length.
            auto* limited = builder()->addTmp("limited", builder()->memberCall(state().cur, "limit", {length}));

            // Establish limited view, remembering position to continue at.
            auto pstate = state();
            pstate.cur = limited;
            pstate.ncur = builder()->addTmp("ncur", builder()->memberCall(state().cur, "advance", {length}));
            pushState(std::move(pstate));
        }

        if ( const auto& skip_pre = p->unitType()->propertyItem("%skip-pre") )
            skipRegExp(skip_pre->expression());

        if ( const auto& skip = p->unitType()->propertyItem("%skip") )
            skipRegExp(skip->expression());

        // Precompute sync points for each field.
        auto sync_points = std::vector<std::optional<uint64_t>>();
        sync_points.reserve(p->fields().size());
        for ( const auto xs : hilti::util::enumerate(p->fields()) ) {
            const uint64_t field_counter = std::get<0>(xs);

            bool found_sync_point = false;

            for ( auto candidate_counter = field_counter + 1; candidate_counter < p->fields().size();
                  ++candidate_counter )
                if ( auto* candidate = p->fields()[candidate_counter]->meta().field();
                     candidate && candidate->attributes()->find(attribute::kind::Synchronize) ) {
                    sync_points.emplace_back(candidate_counter);
                    found_sync_point = true;
                    break;
                }

            // If no sync point was found for this field store a None for it.
            if ( ! found_sync_point )
                sync_points.emplace_back();
        }

        // Group adjacent fields with same sync point.
        std::vector<std::pair<std::vector<uint64_t>, std::optional<uint64_t>>> groups;
        for ( uint64_t i = 0; i < sync_points.size(); ++i ) {
            const auto& sync_point = sync_points[i];
            if ( ! groups.empty() && groups.back().second == sync_point )
                groups.back().first.push_back(i);
            else
                groups.push_back({{i}, sync_point});
        }

        auto parse_field = [&](const auto& field_production) {
            parseProduction(*field_production);

            if ( const auto& skip = p->unitType()->propertyItem("%skip") )
                skipRegExp(skip->expression());
        };

        int trial_loops = 0;

        // Process fields in groups of same sync point.
        for ( const auto& group : groups ) {
            const auto& fields = group.first;
            const auto& sync_point = group.second;

            assert(! fields.empty());

            auto maybe_try = std::optional<decltype(std::declval<Builder>().addTry())>();

            if ( ! sync_point )
                for ( auto field : fields )
                    parse_field(p->fields()[field]);

            else {
                auto try_ = builder()->addTry();

                pushBuilder(try_.first, [&]() {
                    for ( auto field : fields )
                        parse_field(p->fields()[field]);
                });

                pushBuilder(try_.second.addCatch(
                                builder()->parameter(ID("e"), builder()->typeName("hilti::RecoverableFailure"))),
                            [&]() {
                                // There is a sync point; run its production w/o consuming input until parsing
                                // succeeds or we run out of data.
                                builder()->addDebugMsg("spicy-verbose",
                                                       fmt("failed to parse, will try to synchronize at '%s'",
                                                           p->fields()[*sync_point]->meta().field()->id()));

                                // Remember the original error so we can report it in case the sync failed.
                                builder()->addAssign(state().error, builder()->id("e"));
                            });

                startSynchronize(*p->fields()[*sync_point]);
                ++trial_loops;
            }
        }

        if ( const auto& skip_post = p->unitType()->propertyItem("%skip-post") )
            skipRegExp(skip_post->expression());

        pb->finalizeUnit(true, p->location());

        for ( int i = 0; i < trial_loops; ++i )
            finishSynchronize();

        if ( auto* a = p->unitType()->attributes()->find(attribute::kind::MaxSize) ) {
            // Check that we did not read into the sentinel byte.
            auto* cond = builder()->greaterEqual(builder()->memberCall(state().cur, "offset"),
                                                 builder()->memberCall(state().ncur, "offset"));
            auto exceeded = builder()->addIf(cond);
            pushBuilder(std::move(exceeded),
                        [&]() { pb->parseError("parsing not done within &max-size bytes", a->meta()); });

            // Restore parser state.
            auto* limited = state().cur;
            popState();
            builder()->addAssign(state().cur, advanceLimited(state().cur, limited));
        }

        else if ( auto* a = p->unitType()->attributes()->find(attribute::kind::Size);
                  a && ! p->unitType()->attributes()->find(attribute::kind::Eod) ) {
            auto* ncur = state().ncur;
            auto* length = pb->evaluateAttributeExpression(a, "size");
            _checkSizeAmount(length, a->meta(), ncur);
            popState();
            builder()->addAssign(state().cur, ncur);
        }

        popState();
    }

    void operator()(const production::Ctor* p) final { pb->parseLiteral(*p, destination(true)); }

    auto parseLookAhead(const production::LookAhead& p) {
        if ( auto* c = p.condition() )
            pushBuilder(builder()->addIf(c));

        // If we don't have a look-ahead symbol pending, get one.
        auto true_ = builder()->addIf(builder()->not_(state().lahead));
        pushBuilder(std::move(true_));
        getLookAhead(p);
        popBuilder();

        // Now use the freshly set look-ahead symbol to switch accordingly.
        const auto& lahs = p.lookAheads();

        auto alts1 = lahs.first | std::views::filter([](const auto& p) { return p->isLiteral(); });
        auto alts2 = lahs.second | std::views::filter([](const auto& p) { return p->isLiteral(); });
        auto exprs_alt1 = hilti::util::toVector(alts1 | std::views::transform([this](const auto& p) -> Expression* {
                                                    return builder()->integer(p->tokenID());
                                                }));
        auto exprs_alt2 = hilti::util::toVector(alts2 | std::views::transform([this](const auto& p) -> Expression* {
                                                    return builder()->integer(p->tokenID());
                                                }));

        switch ( p.default_() ) {
            case production::look_ahead::Default::First: {
                exprs_alt1.push_back(builder()->integer(look_ahead::None));
                break;
            }
            case production::look_ahead::Default::Second: {
                exprs_alt2.push_back(builder()->integer(look_ahead::None));
                break;
            }
            case production::look_ahead::Default::None: {
                break;
            }
        }

        // If one alternative has no look-aheads and is just epsilon, then
        // EOD is OK and we go there if we haven't found a look-ahead symbol.
        bool eod_handled = true;

        if ( lahs.first.empty() && p.alternatives().first->isA<production::Epsilon>() )
            exprs_alt1.push_back(builder()->integer(look_ahead::Eod));
        else if ( lahs.second.empty() && p.alternatives().second->isA<production::Epsilon>() )
            exprs_alt2.push_back(builder()->integer(look_ahead::Eod));
        else
            eod_handled = false;

        auto switch_ = builder()->addSwitch(state().lahead);
        auto builder_alt1 = switch_.addCase(exprs_alt1);
        auto builder_alt2 = switch_.addCase(exprs_alt2);

        if ( ! eod_handled ) {
            auto builder_eod = switch_.addCase(builder()->integer(look_ahead::Eod));
            pushBuilder(std::move(builder_eod));
            pb->parseError("expected look-ahead token, but reached end-of-data", p.location());
            popBuilder();
        }

        auto builder_default = switch_.addDefault();

        if ( p.condition() )
            popBuilder();

        return std::make_tuple(builder_alt1, builder_alt2, builder_default);
    }

    void operator()(const production::LookAhead* p) final {
        auto [builder_alt1, builder_alt2, builder_default] = parseLookAhead(*p);

        pushBuilder(std::move(builder_alt1));
        parseProduction(*p->alternatives().first);
        popBuilder();

        pushBuilder(std::move(builder_alt2));
        parseProduction(*p->alternatives().second);
        popBuilder();

        pushBuilder(std::move(builder_default),
                    [&]() { pb->parseError("no expected look-ahead token found", p->location()); });
    }

    void operator()(const production::Sequence* p) final {
        for ( const auto& i : p->sequence() )
            parseProduction(*i);
    }

    void operator()(const production::Skip* p) final {
        if ( auto* c = p->field()->condition() )
            pushBuilder(builder()->addIf(c));

        if ( const auto& ctor = p->ctor() )
            pb->skipLiteral(*ctor);

        else if ( const auto& size = p->field()->size(context()) )
            pb->skip(size, p->location());

        else if ( p->field()->parseType()->type()->isA<hilti::type::Bytes>() ) {
            auto* eod_attr = p->field()->attributes()->find(attribute::kind::Eod);
            auto* until_attr = p->field()->attributes()->find(attribute::kind::Until);
            if ( ! until_attr )
                until_attr = p->field()->attributes()->find(attribute::kind::UntilIncluding);

            if ( eod_attr ) {
                builder()->addDebugMsg("spicy-verbose", "- skipping to eod");
                auto loop = builder()->addWhile(pb->waitForInputOrEod());
                pushBuilder(std::move(loop), [&]() { pb->advanceInput(builder()->size(state().cur)); });
                pb->advanceInput(builder()->size(state().cur));
            }

            else if ( until_attr ) {
                Expression* until_expr =
                    builder()->coerceTo(pb->evaluateAttributeExpression(until_attr, "until"),
                                        builder()->qualifiedType(builder()->typeBytes(), hilti::Constness::Const));
                auto* until_bytes_var = builder()->addTmp("until_bytes", until_expr);
                auto* until_bytes_size_var = builder()->addTmp("until_bytes_sz", builder()->size(until_bytes_var));

                auto body = builder()->addWhile(builder()->bool_(true));
                pushBuilder(std::move(body), [&]() {
                    pb->waitForInput(until_bytes_size_var, "end-of-data reached before &until expression found",
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

                    auto [found_branch, not_found_branch] = builder()->addIfElse(found);

                    pushBuilder(std::move(found_branch), [&]() {
                        auto* new_it = builder()->sum(it, until_bytes_size_var);
                        pb->advanceInput(new_it);
                        builder()->addBreak();
                    });

                    pushBuilder(std::move(not_found_branch), [&]() { pb->advanceInput(it); });
                });
            }
        }

        else
            hilti::logger().internalError("unexpected skip production");

        if ( p->field()->condition() )
            popBuilder();
    }

    void operator()(const production::Variable* p) final {
        pb->parseType(p->type()->type(), p->meta(), destination(true), TypesMode::Default);
    }

    void operator()(const production::While* p) final {
        if ( p->expression() )
            hilti::logger().internalError("expression-based while loop not implemented in parser builder");
        else {
            // Look-ahead based loop.
            auto body = builder()->addWhile(builder()->bool_(true));
            pushBuilder(std::move(body), [&]() {
                // If we don't have any input right now, we suspend because
                // we might get an EOD next, in which case we need to abort the loop.
                builder()->addExpression(pb->waitForInputOrEod(builder()->integer(1)));

                const auto* lah_prod = p->lookAheadProduction();

                std::shared_ptr<Builder> builder_alt1;
                std::shared_ptr<Builder> builder_alt2;
                std::shared_ptr<Builder> builder_default;
                auto parse = [&]() {
                    std::tie(builder_alt1, builder_alt2, builder_default) = parseLookAhead(*lah_prod);
                };

                // If the list field generating this While is a synchronization point, set up a try/catch block
                // for internal list synchronization (failure to parse a list element tries to synchronize at
                // the next possible list element).
                if ( auto* field = p->body()->meta().field();
                     field && field->attributes() && field->attributes()->find(attribute::kind::Synchronize) ) {
                    auto try_ = builder()->addTry();

                    pushBuilder(try_.first, [&]() { parse(); });

                    pushBuilder(try_.second.addCatch(
                                    builder()->parameter(ID("e"), builder()->typeName("hilti::RecoverableFailure"))),
                                [&]() {
                                    // Remember the original error so we can report it in case the sync failed.
                                    builder()->addAssign(state().error, builder()->id("e"));

                                    builder()->addDebugMsg("spicy-verbose",
                                                           "failed to parse list element, will try to "
                                                           "synchronize at next possible element");

                                    syncProductionNext(*p);
                                });

                    pushBuilder(std::move(builder_default),
                                [&]() { pb->parseError("no expected look-ahead token found", p->location()); });
                }
                else {
                    parse();

                    pushBuilder(std::move(builder_default), [&]() {
                        // Terminate loop.
                        builder()->addBreak();
                    });
                }

                pushBuilder(std::move(builder_alt1), [&]() {
                    // Terminate loop.
                    builder()->addBreak();
                });

                pushBuilder(std::move(builder_alt2), [&]() {
                    // Parse body.
                    auto* cookie = pb->initLoopBody();
                    auto* stop = parseProduction(*p->body());
                    auto b = builder()->addIf(stop);
                    b->addBreak();

                    pb->finishLoopBody(cookie, p->location());
                });
            });
        };
    }
}; // namespace spicy::detail::codegen

} // namespace spicy::detail::codegen

static auto parseMethodIDs(const type::Unit& t) {
    assert(t.typeID());
    return std::make_tuple(ID(fmt("%s::parse1", t.typeID())), ID(fmt("%s::parse2", t.typeID())),
                           ID(fmt("%s::parse3", t.typeID())), ID(fmt("%s::context_new", t.typeID())));
}

ParserBuilder::ParserBuilder(CodeGen* cg) : _cg(cg) {}

hilti::type::Function* ParserBuilder::parseMethodFunctionType(hilti::type::function::Parameter* addl_param,
                                                              const Meta& m) {
    auto* result = builder()->typeTuple(
        {builder()->qualifiedType(builder()->typeStreamView(), hilti::Constness::Const), lookAheadType(),
         builder()->qualifiedType(builder()->typeStreamIterator(), hilti::Constness::Const),
         builder()->qualifiedType(builder()->typeOptional(
                                      builder()->qualifiedType(builder()->typeName("hilti::RecoverableFailure"),
                                                               hilti::Constness::Const)),
                                  hilti::Constness::Const)});

    auto params = hilti::declaration::Parameters{
        builder()->parameter(HILTI_INTERNAL_ID("data"),
                             builder()->typeValueReference(
                                 builder()->qualifiedType(builder()->typeStream(), hilti::Constness::Mutable)),
                             hilti::parameter::Kind::InOut),
        builder()->parameter(HILTI_INTERNAL_ID("begin"), builder()->typeStreamIterator(), hilti::parameter::Kind::In),
        builder()->parameter(HILTI_INTERNAL_ID("cur"), builder()->typeStreamView(), hilti::parameter::Kind::Copy),
        builder()->parameter(HILTI_INTERNAL_ID("trim"), builder()->typeBool(), hilti::parameter::Kind::Copy),
        builder()->parameter(HILTI_INTERNAL_ID("lah"), lookAheadType()->type(), hilti::parameter::Kind::Copy),
        builder()->parameter(HILTI_INTERNAL_ID("lahe"), builder()->typeStreamIterator(), hilti::parameter::Kind::Copy),
        builder()->parameter(HILTI_INTERNAL_ID("error"),
                             builder()->typeOptional(
                                 builder()->qualifiedType(builder()->typeName("hilti::RecoverableFailure"),
                                                          hilti::Constness::Const)),
                             hilti::parameter::Kind::Copy),
    };

    if ( addl_param )
        params.push_back(addl_param);

    return builder()->typeFunction(builder()->qualifiedType(result, hilti::Constness::Const), params,
                                   hilti::type::function::Flavor::Method,
                                   hilti::type::function::CallingConvention::Standard, m);
}

ASTContext* ParserBuilder::context() const { return _cg->context(); }

const hilti::Options& ParserBuilder::options() const { return _cg->options(); }

std::shared_ptr<Builder> ParserBuilder::pushBuilder() {
    _builders.emplace_back(std::make_shared<Builder>(context()));
    return _builders.back();
}

void ParserBuilder::addParserMethods(hilti::type::Struct* s, type::Unit* t, bool declare_only) {
    auto [id_ext_overload1, id_ext_overload2, id_ext_overload3, id_ext_context_new] = parseMethodIDs(*t);

    hilti::declaration::Parameters params =
        {builder()->parameter(HILTI_INTERNAL_ID("data"),
                              builder()->typeValueReference(
                                  builder()->qualifiedType(builder()->typeStream(), hilti::Constness::Mutable)),
                              hilti::parameter::Kind::InOut),
         builder()->parameter(HILTI_INTERNAL_ID("cur"),
                              builder()->typeOptional(
                                  builder()->qualifiedType(builder()->typeStreamView(), hilti::Constness::Mutable)),
                              builder()->optional(
                                  builder()->qualifiedType(builder()->typeStreamView(), hilti::Constness::Mutable))),
         builder()->parameter(HILTI_INTERNAL_ID("context"),
                              builder()->typeOptional(
                                  builder()->qualifiedType(builder()->typeName("spicy_rt::UnitContext"),
                                                           hilti::Constness::Mutable)))};

    auto* attr_ext_overload = builder()->attributeSet(
        {builder()->attribute(hilti::attribute::kind::NeededByFeature, builder()->stringLiteral("is_filter")),
         builder()->attribute(hilti::attribute::kind::NeededByFeature, builder()->stringLiteral("supports_sinks")),
         builder()->attribute(hilti::attribute::kind::Static), builder()->attribute(hilti::attribute::kind::Public)});

    auto* f_ext_overload1_result = builder()->qualifiedType(builder()->typeStreamView(), hilti::Constness::Mutable);
    auto* f_ext_overload1 =
        builder()->function(id_ext_overload1, f_ext_overload1_result, params, hilti::type::function::Flavor::Method,
                            hilti::declaration::Linkage::Struct, hilti::type::function::CallingConvention::Extern,
                            attr_ext_overload, t->meta());

    auto* f_ext_overload2_result = builder()->qualifiedType(builder()->typeStreamView(), hilti::Constness::Mutable);
    auto* f_ext_overload2 = builder()->function(
        id_ext_overload2, f_ext_overload2_result,
        {builder()->parameter(HILTI_INTERNAL_ID("unit"),
                              builder()->typeValueReference(builder()->qualifiedType(builder()->typeName(t->typeID()),
                                                                                     hilti::Constness::Mutable)),
                              hilti::parameter::Kind::InOut),
         builder()->parameter(HILTI_INTERNAL_ID("data"),
                              builder()->typeValueReference(
                                  builder()->qualifiedType(builder()->typeStream(), hilti::Constness::Mutable)),
                              hilti::parameter::Kind::InOut),
         builder()->parameter(HILTI_INTERNAL_ID("cur"),
                              builder()->typeOptional(
                                  builder()->qualifiedType(builder()->typeStreamView(), hilti::Constness::Mutable)),
                              builder()->optional(
                                  builder()->qualifiedType(builder()->typeStreamView(), hilti::Constness::Mutable))),
         builder()->parameter(HILTI_INTERNAL_ID("context"),
                              builder()->typeOptional(
                                  builder()->qualifiedType(builder()->typeName("spicy_rt::UnitContext"),
                                                           hilti::Constness::Mutable)))},
        hilti::type::function::Flavor::Method, hilti::declaration::Linkage::Struct,
        hilti::type::function::CallingConvention::Extern, attr_ext_overload, t->meta());

    auto* f_ext_overload3_result = builder()->qualifiedType(builder()->typeStreamView(), hilti::Constness::Mutable);
    auto* f_ext_overload3 =
        builder()
            ->function(id_ext_overload3, f_ext_overload3_result,
                       {builder()->parameter(HILTI_INTERNAL_ID("gunit"),
                                             builder()->typeValueReference(
                                                 builder()->qualifiedType(builder()->typeName("spicy_rt::ParsedUnit"),
                                                                          hilti::Constness::Mutable)),
                                             hilti::parameter::Kind::InOut),
                        builder()->parameter(HILTI_INTERNAL_ID("data"),
                                             builder()->typeValueReference(
                                                 builder()->qualifiedType(builder()->typeStream(),
                                                                          hilti::Constness::Mutable)),
                                             hilti::parameter::Kind::InOut),
                        builder()->parameter(HILTI_INTERNAL_ID("cur"),
                                             builder()->typeOptional(
                                                 builder()->qualifiedType(builder()->typeStreamView(),
                                                                          hilti::Constness::Mutable)),
                                             builder()->optional(builder()->qualifiedType(builder()->typeStreamView(),
                                                                                          hilti::Constness::Mutable))),
                        builder()->parameter(HILTI_INTERNAL_ID("context"),
                                             builder()->typeOptional(
                                                 builder()->qualifiedType(builder()->typeName("spicy_rt::UnitContext"),
                                                                          hilti::Constness::Mutable)))},
                       hilti::type::function::Flavor::Method, hilti::declaration::Linkage::Struct,
                       hilti::type::function::CallingConvention::Extern, attr_ext_overload, t->meta());

    auto* f_ext_context_new_result =
        builder()->qualifiedType(builder()->typeName("spicy_rt::UnitContext"), hilti::Constness::Mutable);
    auto* f_ext_context_new =
        builder()->function(id_ext_context_new, f_ext_context_new_result, {}, hilti::type::function::Flavor::Method,
                            hilti::declaration::Linkage::Struct,
                            hilti::type::function::CallingConvention::ExternNoSuspend,
                            builder()->attributeSet({builder()->attribute(hilti::attribute::kind::Static)}), t->meta());

    // We only actually add the functions we just build if the unit is
    // publicly exposed. We still build their code in either case below
    // because doing so triggers generation of the whole parser, including
    // the internal parsing functions.
    auto* sf_ext_overload1 =
        builder()->declarationField(f_ext_overload1->id().local(), f_ext_overload1->function()->ftype(),
                                    f_ext_overload1->function()->attributes());

    auto* sf_ext_overload2 =
        builder()->declarationField(f_ext_overload2->id().local(), f_ext_overload2->function()->ftype(),
                                    f_ext_overload2->function()->attributes());

    auto* sf_ext_overload3 =
        builder()->declarationField(f_ext_overload3->id().local(), f_ext_overload3->function()->ftype(),
                                    f_ext_overload3->function()->attributes());

    s->addField(context(), sf_ext_overload1);
    s->addField(context(), sf_ext_overload2);
    s->addField(context(), sf_ext_overload3);

    if ( t->contextType() ) {
        auto* sf_ext_ctor =
            builder()->declarationField(f_ext_context_new->id().local(), f_ext_context_new->function()->ftype(),
                                        f_ext_context_new->function()->attributes());

        s->addField(context(), sf_ext_ctor);
    }

    if ( ! declare_only ) {
        const auto* grammar = cg()->grammarBuilder()->grammar(*t);
        if ( ! grammar ) {
            // not computed, presumably due to an earlier error
            HILTI_DEBUG(spicy::logging::debug::ParserBuilder,
                        fmt("no grammar available for %s, skipping parser generation", t->canonicalID()));
            return;
        }

        auto visitor = ProductionVisitor(this, *grammar);

        // Helper to initialize a unit's `$context` attribute. We use
        // a parse functions "context" argument if that was provided,
        // and otherwise create a default instanc of the unit's context type.
        auto init_context = [&]() {
            auto* context = t->contextType();
            if ( ! context )
                return;

            auto* arg_ctx = builder()->id(HILTI_INTERNAL_ID("context"));
            auto* create_ctx = builder()->memberCall(builder()->id(HILTI_INTERNAL_ID("unit")), "context_new");
            auto* ctx = builder()->ternary(arg_ctx, builder()->deref(arg_ctx), create_ctx);

            builder()->addCall("spicy_rt::setContext",
                               {builder()->member(builder()->id(HILTI_INTERNAL_ID("unit")),
                                                  HILTI_INTERNAL_ID("context")),
                                ctx, builder()->typeinfo(builder()->qualifiedType(context, hilti::Constness::Const))});
        };

        HILTI_DEBUG(spicy::logging::debug::ParserBuilder, fmt("creating parser for %s", t->canonicalID()));
        hilti::logging::DebugPushIndent _(spicy::logging::debug::ParserBuilder);

        const auto& parameters = t->parameters();
        // Only create `parse1` and `parse3` body if the unit can be default constructed.
        if ( std::ranges::all_of(parameters, [](const auto& p) { return p->default_(); }) ) {
            // Create parse1() body.
            pushBuilder();
            builder()->setLocation(grammar->root()->location());
            builder()->addLocal(HILTI_INTERNAL_ID("unit"),
                                builder()->valueReference(
                                    builder()->default_(builder()->typeName(t->typeID()),
                                                        hilti::util::toVector(
                                                            t->parameters() |
                                                            std::views::transform([](const auto& p) -> Expression* {
                                                                return p->default_();
                                                            })))));
            builder()
                ->addLocal(HILTI_INTERNAL_ID("ncur"),
                           builder()->qualifiedType(builder()->typeStreamView(), hilti::Constness::Mutable),
                           builder()->ternary(builder()->id(HILTI_INTERNAL_ID("cur")),
                                              builder()->deref(builder()->id(HILTI_INTERNAL_ID("cur"))),
                                              builder()->cast(builder()->deref(
                                                                  builder()->id(HILTI_INTERNAL_ID("data"))),
                                                              builder()->qualifiedType(builder()->typeStreamView(),
                                                                                       hilti::Constness::Mutable))));
            builder()->addLocal(HILTI_INTERNAL_ID("lahead"), lookAheadType(), builder()->integer(look_ahead::None));
            builder()->addLocal(HILTI_INTERNAL_ID("lahead_end"),
                                builder()->qualifiedType(builder()->typeStreamIterator(), hilti::Constness::Mutable));
            builder()->addLocal(HILTI_INTERNAL_ID("error"),
                                builder()->optional(
                                    builder()->qualifiedType(builder()->typeName("hilti::RecoverableFailure"),
                                                             hilti::Constness::Const)));

            init_context();

            auto pstate = ParserState(builder(), t, *grammar, builder()->id(HILTI_INTERNAL_ID("data")),
                                      builder()->id(HILTI_INTERNAL_ID("cur")));
            pstate.self = builder()->id(HILTI_INTERNAL_ID("unit"));
            pstate.begin = builder()->begin(builder()->id(HILTI_INTERNAL_ID("ncur")));
            pstate.cur = builder()->id(HILTI_INTERNAL_ID("ncur"));
            pstate.trim = builder()->bool_(true);
            pstate.lahead = builder()->id(HILTI_INTERNAL_ID("lahead"));
            pstate.lahead_end = builder()->id(HILTI_INTERNAL_ID("lahead_end"));
            pstate.error = builder()->id(HILTI_INTERNAL_ID("error"));
            pushState(pstate);
            visitor.pushDestination(pstate.self);
            visitor.parseProduction(*grammar->root(), true);

            // Check if the unit never left trial mode.
            pushBuilder(builder()->addIf(state().error), [&]() {
                builder()->addDebugMsg("spicy", "successful sync never confirmed, failing unit");
                auto* original_error = builder()->deref(state().error);
                parseError("successful synchronization never confirmed: %s", original_error);
            });

            builder()->addReturn(state().cur);
            popState();

            auto body_ext_overload1 = popBuilder();
            f_ext_overload1->function()->setBody(context(), body_ext_overload1->block());
            cg()->addDeclaration(f_ext_overload1);

            // Create parse3() body.
            pushBuilder();
            builder()->setLocation(grammar->root()->location());
            builder()->addLocal(HILTI_INTERNAL_ID("unit"),
                                builder()->valueReference(
                                    builder()->default_(builder()->typeName(t->typeID()),
                                                        hilti::util::toVector(
                                                            t->parameters() |
                                                            std::views::transform([](const auto& p) -> Expression* {
                                                                return p->default_();
                                                            })))));

            builder()->addCall(ID("spicy_rt::initializeParsedUnit"),
                               {builder()->id(HILTI_INTERNAL_ID("gunit")), builder()->id(HILTI_INTERNAL_ID("unit"))});
            builder()
                ->addLocal(HILTI_INTERNAL_ID("ncur"),
                           builder()->qualifiedType(builder()->typeStreamView(), hilti::Constness::Mutable),
                           builder()->ternary(builder()->id(HILTI_INTERNAL_ID("cur")),
                                              builder()->deref(builder()->id(HILTI_INTERNAL_ID("cur"))),
                                              builder()->cast(builder()->deref(
                                                                  builder()->id(HILTI_INTERNAL_ID("data"))),
                                                              builder()->qualifiedType(builder()->typeStreamView(),
                                                                                       hilti::Constness::Mutable))));
            builder()->addLocal(HILTI_INTERNAL_ID("lahead"), lookAheadType(), builder()->integer(look_ahead::None));
            builder()->addLocal(HILTI_INTERNAL_ID("lahead_end"),
                                builder()->qualifiedType(builder()->typeStreamIterator(), hilti::Constness::Mutable));
            builder()->addLocal(HILTI_INTERNAL_ID("error"),
                                builder()->optional(
                                    builder()->qualifiedType(builder()->typeName("hilti::RecoverableFailure"),
                                                             hilti::Constness::Const)));

            init_context();

            pstate = ParserState(builder(), t, *grammar, builder()->id(HILTI_INTERNAL_ID("data")),
                                 builder()->id(HILTI_INTERNAL_ID("cur")));
            pstate.self = builder()->id(HILTI_INTERNAL_ID("unit"));
            pstate.begin = builder()->begin(builder()->id(HILTI_INTERNAL_ID("ncur")));
            pstate.cur = builder()->id(HILTI_INTERNAL_ID("ncur"));
            pstate.trim = builder()->bool_(true);
            pstate.lahead = builder()->id(HILTI_INTERNAL_ID("lahead"));
            pstate.lahead_end = builder()->id(HILTI_INTERNAL_ID("lahead_end"));
            pstate.error = builder()->id(HILTI_INTERNAL_ID("error"));
            pushState(pstate);
            visitor.pushDestination(pstate.self);
            visitor.parseProduction(*grammar->root(), true);

            // Check if the unit never left trial mode.
            pushBuilder(builder()->addIf(state().error), [&]() {
                builder()->addDebugMsg("spicy", "successful sync never confirmed, failing unit");
                auto* original_error = builder()->deref(state().error);
                parseError("successful synchronization never confirmed: %s", original_error);
            });

            builder()->addReturn(state().cur);

            popState();

            auto body_ext_overload3 = popBuilder();
            f_ext_overload3->function()->setBody(context(), body_ext_overload3->block());
            cg()->addDeclaration(f_ext_overload3);
        }

        // Create parse2() body.
        pushBuilder();
        builder()->setLocation(grammar->root()->location());
        builder()->addLocal(HILTI_INTERNAL_ID("ncur"),
                            builder()->qualifiedType(builder()->typeStreamView(), hilti::Constness::Mutable),
                            builder()->ternary(builder()->id(HILTI_INTERNAL_ID("cur")),
                                               builder()->deref(builder()->id(HILTI_INTERNAL_ID("cur"))),
                                               builder()->cast(builder()->deref(
                                                                   builder()->id(HILTI_INTERNAL_ID("data"))),
                                                               builder()->qualifiedType(builder()->typeStreamView(),
                                                                                        hilti::Constness::Mutable))));
        builder()->addLocal(HILTI_INTERNAL_ID("lahead"), lookAheadType(), builder()->integer(look_ahead::None));
        builder()->addLocal(HILTI_INTERNAL_ID("lahead_end"),
                            builder()->qualifiedType(builder()->typeStreamIterator(), hilti::Constness::Mutable));
        builder()->addLocal(HILTI_INTERNAL_ID("error"),
                            builder()->optional(
                                builder()->qualifiedType(builder()->typeName("hilti::RecoverableFailure"),
                                                         hilti::Constness::Const)));

        init_context();

        auto pstate = ParserState(builder(), t, *grammar, builder()->id(HILTI_INTERNAL_ID("data")),
                                  builder()->id(HILTI_INTERNAL_ID("cur")));
        pstate.self = builder()->id(HILTI_INTERNAL_ID("unit"));
        pstate.begin = builder()->begin(builder()->id(HILTI_INTERNAL_ID("ncur")));
        pstate.cur = builder()->id(HILTI_INTERNAL_ID("ncur"));
        pstate.trim = builder()->bool_(true);
        pstate.lahead = builder()->id(HILTI_INTERNAL_ID("lahead"));
        pstate.lahead_end = builder()->id(HILTI_INTERNAL_ID("lahead_end"));
        pstate.error = builder()->id(HILTI_INTERNAL_ID("error"));
        pushState(pstate);
        visitor.pushDestination(pstate.self);
        visitor.parseProduction(*grammar->root(), true);

        // Check if the unit never left trial mode.
        pushBuilder(builder()->addIf(state().error), [&]() {
            builder()->addDebugMsg("spicy", "successful sync never confirmed, failing unit");
            auto* original_error = builder()->deref(state().error);
            parseError("successful synchronization never confirmed: %s", original_error);
        });

        builder()->addReturn(state().cur);
        popState();

        auto body_ext_overload2 = popBuilder();
        f_ext_overload2->function()->setBody(context(), body_ext_overload2->block());
        cg()->addDeclaration(f_ext_overload2);

        if ( auto* ctx = t->contextType() ) {
            // Create context_new() body.
            pushBuilder();
            auto* obj = builder()->new_(ctx);
            builder()->addReturn(builder()->call("spicy_rt::createContext", {obj}));
            auto body_ext_context_new = popBuilder();

            f_ext_context_new->function()->setBody(context(), body_ext_context_new->block());
            cg()->addDeclaration(f_ext_context_new);
        }

        for ( auto* f : visitor.new_fields )
            s->addField(context(), f);
    }

    s->addField(context(), builder()->declarationField(
                               ID(HILTI_INTERNAL_ID("error")),
                               builder()->qualifiedType(builder()->typeOptional(
                                                            builder()->qualifiedType(builder()->typeName(
                                                                                         "hilti::RecoverableFailure"),
                                                                                     hilti::Constness::Const)),
                                                        hilti::Constness::Mutable),
                               builder()->attributeSet({builder()->attribute(hilti::attribute::kind::AlwaysEmit),
                                                        builder()->attribute(hilti::attribute::kind::Internal)})));
}

Builder* ParserBuilder::builder() const { return _builders.empty() ? _cg->builder() : _builders.back().get(); }

Expression* ParserBuilder::parseMethodExternalOverload1(const type::Unit& t) {
    auto id = std::get<0>(parseMethodIDs(t));
    return builder()->expressionName(id);
}

Expression* ParserBuilder::parseMethodExternalOverload2(const type::Unit& t) {
    auto id = std::get<1>(parseMethodIDs(t));
    return builder()->expressionName(id);
}

Expression* ParserBuilder::parseMethodExternalOverload3(const type::Unit& t) {
    auto id = std::get<2>(parseMethodIDs(t));
    return builder()->expressionName(id);
}

Expression* ParserBuilder::contextNewFunction(const type::Unit& t) {
    auto id = std::get<3>(parseMethodIDs(t));
    return builder()->expressionName(id);
}

void ParserBuilder::newValueForField(const production::Meta& meta, Expression* value, Expression* dd) {
    const auto& field = meta.field();

    for ( const auto& a : field->attributes()->findAll(attribute::kind::Requires) ) {
        // We evaluate "&requires" here so that the field's value has been
        // set already, and is hence accessible to the condition through
        // "self.<x>".
        auto block = builder()->addBlock();

        if ( ! field->parseType()->type()->isA<hilti::type::Void>() && ! field->isSkip() )
            block->addLocal(ID(HILTI_INTERNAL_ID("dd")), field->ddType(), dd);

        auto* cond = block->addTmp("requires", *a->valueAsExpression());
        pushBuilder(block->addIf(builder()->not_(cond)),
                    [&]() { parseError(builder()->memberCall(cond, "error"), a->location()); });
    }

    if ( ! field->originalType()->type()->isA<hilti::type::Bitfield>() &&
         ! value->type()->type()->isA<hilti::type::Void>() && ! field->isSkip() ) {
        builder()->addDebugMsg("spicy", fmt("%s = %%s", field->id()), {value});
        builder()->addDebugMsg("spicy-verbose", fmt("- setting field '%s' to '%%s'", field->id()), {value});
    }

    for ( const auto& s : field->sinks() ) {
        builder()->addDebugMsg("spicy-verbose", "- writing %" PRIu64 " bytes to sink", {builder()->size(value)});
        builder()->addMemberCall(s, "write", {value, builder()->null(), builder()->null()}, field->meta());
    }

    if ( field->emitHook() ) {
        beforeHook();

        Expressions args = {value};

        if ( field->originalType()->type()->isA<hilti::type::RegExp>() && ! field->isContainer() ) {
            if ( state().captures )
                args.push_back(state().captures);
            else
                args.push_back(builder()->default_(builder()->typeName("hilti::Captures")));
        }

        if ( value->type()->type()->isA<hilti::type::Void>() || field->isSkip() )
            // Special-case: No value parsed, but still run hook.
            builder()->addMemberCall(state().self, ID(fmt(HILTI_INTERNAL_ID("on_%s"), field->id().local())), {},
                                     field->meta());
        else
            builder()->addMemberCall(state().self, ID(fmt(HILTI_INTERNAL_ID("on_%s"), field->id().local())), args,
                                     field->meta());

        afterHook();
    }
}

Expression* ParserBuilder::newContainerItem(const type::unit::item::Field* field,
                                            const type::unit::item::Field* container, Expression* self,
                                            Expression* item, bool need_value) {
    auto* stop = builder()->addTmp("stop", builder()->bool_(false));

    auto push_element = [&]() {
        if ( need_value )
            pushBuilder(builder()->addIf(builder()->not_(stop)),
                        [&]() { builder()->addExpression(builder()->memberCall(self, "push_back", {item})); });
    };

    auto run_hook = [&]() {
        builder()->addDebugMsg("spicy-verbose", "- got container item");
        pushBuilder(builder()->addIf(builder()->not_(stop)), [&]() {
            if ( container->emitHook() ) {
                beforeHook();
                builder()->addMemberCall(state().self,
                                         ID(fmt(HILTI_INTERNAL_ID("on_%s_foreach"), container->id().local())),
                                         {item, stop}, container->meta());
                afterHook();
            }
        });
    };

    auto eval_condition = [&](Expression* cond) {
        pushBuilder(builder()->addBlock(), [&]() {
            builder()->addLocal(HILTI_INTERNAL_ID("dd"), item);
            builder()->addAssign(stop, builder()->or_(stop, cond));
        });
    };

    auto check_requires = [&]() {
        for ( const auto& a : field->attributes()->findAll(attribute::kind::Requires) ) {
            pushBuilder(builder()->addBlock(), [&]() {
                builder()->addLocal(HILTI_INTERNAL_ID("dd"), item);
                auto* cond = evaluateAttributeExpression(a, "requires");
                pushBuilder(builder()->addIf(builder()->not_(cond)),
                            [&]() { parseError(builder()->memberCall(cond, "error"), a->location()); });
            });
        }
    };

    if ( auto* a = container->attributes()->find(attribute::kind::Until) ) {
        eval_condition(*a->valueAsExpression());
        check_requires();
        run_hook();
        push_element();
    }

    else if ( auto* a = container->attributes()->find(attribute::kind::UntilIncluding) ) {
        check_requires();
        run_hook();
        push_element();
        eval_condition(*a->valueAsExpression());
    }

    else if ( auto* a = container->attributes()->find(attribute::kind::While) ) {
        eval_condition(builder()->not_(*a->valueAsExpression()));
        check_requires();
        run_hook();
        push_element();
    }

    else {
        check_requires();
        run_hook();
        push_element();
    }

    return stop;
}

Expression* ParserBuilder::applyConvertExpression(const type::unit::item::Field& field, Expression* value,
                                                  Expression* dst) {
    auto convert = field.convertExpression();
    if ( ! convert )
        return value;

    if ( ! dst )
        dst = builder()->addTmp("converted", field.itemType());

    if ( ! convert->second ) {
        auto block = builder()->addBlock();
        if ( ! field.isSkip() )
            block->addLocal(ID(HILTI_INTERNAL_ID("dd")), field.ddType(), value);

        block->addAssign(dst, convert->first);
    }
    else
        // Unit got its own $convert() method for us to call.
        builder()->addAssign(dst, builder()->memberCall(value, HILTI_INTERNAL_ID("convert")));

    return dst;
}

void ParserBuilder::trimInput(bool force) {
    auto do_trim = [this](const auto& builder) {
        builder->addDebugMsg("spicy-verbose", "- trimming input");
        builder->addExpression(builder->memberCall(state().data, "trim", {builder->begin(state().cur)}));
    };

    if ( force )
        do_trim(builder());
    else
        do_trim(builder()->addIf(state().trim));
}

void ParserBuilder::initializeUnit(const Location& l) {
    guardFeatureCode(state().unit, {"uses_stream"}, [&]() {
        builder()->addAssign(builder()->member(state().self, ID(HILTI_INTERNAL_ID("stream"))), state().data);
    });

    saveParsePosition();

    if ( options().getAuxOption<bool>("spicy.track_offsets", false) ) {
        // _offsets["self"] = (self.offset(), null);
        auto* offsets = builder()->member(state().self, HILTI_INTERNAL_ID("offsets"));
        auto* begin = builder()->memberCall(state().cur, "offset");
        builder()->addAssign(builder()->index(offsets, builder()->string("self", false)),
                             builder()->tuple({begin, builder()->null()}));
    }

    beforeHook();
    builder()->addMemberCall(state().self, HILTI_INTERNAL_ID("on_0x25_init"), {}, l);
    afterHook();
}

void ParserBuilder::finalizeUnit(bool success, const Location& l) {
    const auto& unit = state().unit;

    saveParsePosition();

    if ( options().getAuxOption<bool>("spicy.track_offsets", false) ) {
        // _offsets["self"] = (offsets["self"].begin(), self.offset());
        auto* offsets = builder()->member(state().self, HILTI_INTERNAL_ID("offsets"));
        auto* begin =
            builder()->index(builder()->index(offsets, builder()->string("self", false)), builder()->integer(0U));
        auto* end = builder()->memberCall(state().cur, "offset");
        builder()->addAssign(builder()->index(offsets, builder()->string("self", false)),
                             builder()->tuple({begin, end}));
    }

    if ( success ) {
        // We evaluate any "&requires" before running the final "%done" hook
        // so that (1) that one can rely on the condition, and (2) we keep
        // running either "%done" or "%error".
        for ( const auto& attr : unit->attributes()->findAll(attribute::kind::Requires) ) {
            auto* cond = evaluateAttributeExpression(attr, "requires");
            pushBuilder(builder()->addIf(builder()->not_(cond)),
                        [&]() { parseError(builder()->memberCall(cond, "error"), attr->value()->meta()); });
        }
    }

    if ( success ) {
        beforeHook();
        builder()->addMemberCall(state().self, HILTI_INTERNAL_ID("on_0x25_done"), {}, l);
        afterHook();
    }
    else {
        auto* what = builder()->call("hilti::exception_what", {builder()->id(HILTI_INTERNAL_ID("except"))});
        builder()->addMemberCall(state().self, HILTI_INTERNAL_ID("on_0x25_error"), {what}, l);
    }

    guardFeatureCode(state().unit, {"supports_filters"},
                     [&]() { builder()->addCall("spicy_rt::filter_disconnect", {state().self}); });

    if ( unit->isFilter() )
        guardFeatureCode(state().unit, {"is_filter"},
                         [&]() { builder()->addCall("spicy_rt::filter_forward_eod", {state().self}); });

    guardFeatureCode(state().unit, {"supports_sinks"}, [&]() {
        for ( const auto& s : unit->items<type::unit::item::Sink>() )
            builder()->addMemberCall(builder()->member(state().self, s->id()), "close", {}, l);
    });
}

Expression* ParserBuilder::currentFilters(const ParserState& state) {
    // Since use of a unit's `_filters` member triggers a requirement for
    // filter support, guard access to it behind a feature flag. This allows us
    // to decide with user-written code whether we actually want to enable
    // filter support.
    auto* member = builder()->member(state.self, ID(HILTI_INTERNAL_ID("filters")));

    const auto& type_id = state.unit->typeID();
    if ( ! type_id )
        return member;

    return builder()->ternary(featureConstant(state.unit, "supports_filters"), member,
                              builder()->strongReference(
                                  builder()->qualifiedType(builder()->typeName("spicy_rt::Filters"),
                                                           hilti::Constness::Mutable)));
}

hilti::Attributes ParserBuilder::removeGenericParseAttributes(hilti::AttributeSet* attrs) {
    // List of generic attributes. This isn't perfect because we actually don't
    // really have a well-defined list of attributes that are clearly generic
    // vs field-specific. So this best-effort weeding out attributes that
    // field-specific code usually doesn't need to care about.
    static std::unordered_set<hilti::attribute::Kind> generic_attributes = {
        attribute::kind::AlwaysEmit, attribute::kind::Convert,     attribute::kind::Default,
        attribute::kind::Eod,        attribute::kind::MaxSize,     attribute::kind::Optional,
        attribute::kind::ParseAt,    attribute::kind::ParseFrom,   attribute::kind::Requires,
        attribute::kind::Size,       attribute::kind::Synchronize, attribute::kind::Try,
    };

    hilti::Attributes filtered;
    for ( auto* a : attrs->attributes() ) {
        if ( ! generic_attributes.contains(a->kind()) )
            filtered.emplace_back(a);
    }

    return filtered;
}

Expression* ParserBuilder::waitForInputOrEod() {
    return builder()->call("spicy_rt::waitForInputOrEod", {state().data, state().cur, currentFilters(state())});
}

Expression* ParserBuilder::atEod() {
    return builder()->call("spicy_rt::atEod", {state().data, state().cur, currentFilters(state())});
}

void ParserBuilder::waitForInput(std::string_view error_msg, const Meta& location) {
    builder()->addCall("spicy_rt::waitForInput", {state().data, state().cur, builder()->stringLiteral(error_msg),
                                                  builder()->expression(location), currentFilters(state())});
}

Expression* ParserBuilder::waitForInputOrEod(Expression* min) {
    return builder()->call("spicy_rt::waitForInputOrEod", {state().data, state().cur, min, currentFilters(state())});
}

void ParserBuilder::waitForInput(Expression* min, std::string_view error_msg, const Meta& location) {
    builder()->addCall("spicy_rt::waitForInput", {state().data, state().cur, min, builder()->stringLiteral(error_msg),
                                                  builder()->expression(location), currentFilters(state())});
}

void ParserBuilder::waitForEod() {
    builder()->addCall("spicy_rt::waitForEod", {state().data, state().cur, currentFilters(state())});
}

void ParserBuilder::parseError(Expression* error_msg, const Meta& meta) {
    builder()->addThrow(builder()->exception(builder()->typeName("spicy_rt::ParseError"), error_msg, meta), meta);
}

void ParserBuilder::parseError(std::string_view error_msg, const Meta& meta) {
    parseError(builder()->stringLiteral(error_msg), meta);
}

void ParserBuilder::parseError(std::string_view fmt, const Expressions& args, const Meta& meta) {
    parseError(builder()->modulo(builder()->stringLiteral(fmt), builder()->tuple(args)), meta);
}

void ParserBuilder::parseError(std::string_view fmt, Expression* orig_except) {
    auto* what = builder()->call("hilti::exception_what", {orig_except});
    auto* where = builder()->call("hilti::exception_where", {orig_except});
    auto* msg = builder()->modulo(builder()->stringLiteral(fmt), builder()->tuple({what}));
    builder()->addThrow(builder()->exception(builder()->typeName("spicy_rt::ParseError"), msg, where));
}

void ParserBuilder::skip(Expression* size, const Meta& location) {
    assert(size->type()->type()->isA<hilti::type::UnsignedInteger>());

    auto* n = builder()->addTmp("skip", size);
    auto loop = builder()->addWhile(builder()->greater(n, builder()->integer(0U)));
    pushBuilder(std::move(loop), [&]() {
        waitForInput(builder()->integer(1U), "not enough bytes for skipping", location);
        auto* consume = builder()->addTmp("consume", builder()->min(builder()->size(state().cur), n));
        advanceInput(consume);
        builder()->addAssign(n, builder()->difference(n, consume));
        builder()->addDebugMsg("spicy-verbose", "- skipped %u bytes (%u left to skip)", {consume, n});
    });
}

void ParserBuilder::advanceToNextData() {
    auto* old_offset = builder()->addTmp("old_offset", builder()->memberCall(state().cur, "offset"));

    auto* profiler =
        builder()->startProfiler(hilti::util::fmt("spicy/unit/%s/" HILTI_INTERNAL_ID("sync_advance"), state().unit_id),
                                 old_offset);

    builder()->addAssign(state().cur, builder()->memberCall(state().cur, "advance_to_next_data"));

    auto* new_offset = builder()->memberCall(state().cur, "offset");

    {
        Expression* sync_advance_block_size = nullptr;
        if ( auto* p = state().unit->propertyItem("%sync-advance-block-size"); p && p->expression() )
            sync_advance_block_size = p->expression();
        else
            sync_advance_block_size = builder()->integer(4096); // 4KB default

        auto* old_block = builder()->division(old_offset, sync_advance_block_size);
        auto* new_block = builder()->division(new_offset, sync_advance_block_size);
        auto run_hook = builder()->addIf(builder()->unequal(old_block, new_block));

        syncAdvanceHook(std::move(run_hook));
    }

    if ( profiler )
        // advance_to_next_data() always moves one byte ahead, so we subtract that
        builder()->stopProfiler(profiler, builder()->difference(new_offset, builder()->integer(1)));

    trimInput();
}

void ParserBuilder::advanceInput(Expression* i) {
    if ( i->type()->type()->isA<hilti::type::stream::View>() )
        builder()->addAssign(state().cur, i);
    else
        builder()->addAssign(state().cur, builder()->memberCall(state().cur, "advance", {i}));

    trimInput();
}

void ParserBuilder::setInput(Expression* i) { builder()->addAssign(state().cur, i); }

void ParserBuilder::beforeHook() {
    // Forward the current trial mode state into the unit so hooks see the
    // correct state should they invoke e.g., `reject`.
    //
    // TODO(bbannier): Guard this with a feature flag once
    // https://github.com/zeek/spicy/issues/1108 is fixed.
    builder()->addAssign(builder()->member(state().self, ID(HILTI_INTERNAL_ID("error"))), state().error);

    guardFeatureCode(state().unit, {"uses_random_access", "uses_offset"}, [&]() {
        builder()->addAssign(builder()->member(state().self, ID(HILTI_INTERNAL_ID("position_update"))),
                             builder()->optional(
                                 builder()->qualifiedType(builder()->typeStreamIterator(), hilti::Constness::Mutable)));
    });
}

void ParserBuilder::afterHook() {
    guardFeatureCode(state().unit, {"uses_random_access", "uses_offset"}, [&]() {
        auto* position_update = builder()->member(state().self, ID(HILTI_INTERNAL_ID("position_update")));
        auto advance = builder()->addIf(position_update);
        auto* ncur = builder()->memberCall(state().cur, "advance", {builder()->deref(position_update)});

        if ( state().ncur )
            advance->addAssign(state().ncur, ncur);
        else
            advance->addAssign(state().cur, ncur);

        advance->addAssign(builder()->member(state().self, ID(HILTI_INTERNAL_ID("position_update"))),
                           builder()->optional(
                               builder()->qualifiedType(builder()->typeStreamIterator(), hilti::Constness::Mutable)));
    });

    // Propagate the unit trial mode state back into the global state as it
    // might have been updated in a hook via e.g., `confirm`.
    //
    // TODO(bbannier): Guard this with a feature flag once
    // https://github.com/zeek/spicy/issues/1108 is fixed.
    builder()->addAssign(state().error, builder()->member(state().self, ID(HILTI_INTERNAL_ID("error"))));
}

void ParserBuilder::saveParsePosition() {
    guardFeatureCode(state().unit, {"uses_random_access"}, [&]() {
        builder()->addAssign(builder()->member(state().self, ID(HILTI_INTERNAL_ID("begin"))), state().begin);
    });

    guardFeatureCode(state().unit, {"uses_offset"}, [&]() {
        auto* cur = builder()->memberCall(builder()->begin(state().cur), "offset");
        auto* begin = builder()->memberCall(state().begin, "offset"); // XX

        builder()->addAssign(builder()->member(state().self, ID(HILTI_INTERNAL_ID("offset"))),
                             builder()->cast(builder()->difference(cur, begin),
                                             builder()->qualifiedType(builder()->typeUnsignedInteger(64),
                                                                      hilti::Constness::Const)));
    });
}

void ParserBuilder::consumeLookAhead(Expression* dst) {
    if ( state().unit->mayHaveFilter() )
        hilti::logger().error(
            fmt("look-ahead required when parsing unit '%s', to which a filter might get connected during runtime; "
                "those two features cannot be combined",
                state().unit->typeID()));

    builder()->addDebugMsg("spicy-verbose", "- consuming look-ahead token");

    if ( dst )
        builder()->addAssign(dst, builder()->memberCall(state().cur, "sub", {state().lahead_end}));

    builder()->addAssign(state().lahead, builder()->integer(look_ahead::None));
    advanceInput(state().lahead_end);
}

void ParserBuilder::initBacktracking() {
    auto* try_cur = builder()->addTmp("try_cur", state().cur);
    auto [body, try_] = builder()->addTry();
    auto catch_ = try_.addCatch(builder()->parameter(ID("e"), builder()->typeName("spicy_rt::Backtrack")));
    pushBuilder(std::move(catch_), [&]() { builder()->addAssign(state().cur, try_cur); });

    auto pstate = state();
    pstate.trim = builder()->bool_(false);
    pushState(std::move(pstate));
    pushBuilder(std::move(body));
}

void ParserBuilder::finishBacktracking() {
    popBuilder();
    popState();
    trimInput();
}

Expression* ParserBuilder::initLoopBody() { return builder()->addTmp("old_begin", builder()->begin(state().cur)); }

void ParserBuilder::finishLoopBody(Expression* cookie, const Location& l) {
    auto* not_moved =
        builder()->and_(builder()->equal(builder()->begin(state().cur), cookie), builder()->not_(atEod()));
    auto body = builder()->addIf(not_moved);
    pushBuilder(std::move(body),
                [&]() { parseError("loop body did not change input position, possible infinite loop", l); });
}

void ParserBuilder::syncAdvanceHook(std::shared_ptr<Builder> cond) {
    auto body = [&]() {
        beforeHook();
        auto* offset = builder()->memberCall(state().cur, "offset");
        builder()->addMemberCall(state().self, HILTI_INTERNAL_ID("on_0x25_sync_advance"), {offset});
        afterHook();
    };

    guardFeatureCode(state().unit, {"uses_sync_advance"}, [&]() {
        if ( cond )
            pushBuilder(std::move(cond), body);
        else
            body();
    });
}

std::shared_ptr<Builder> ParserBuilder::_featureCodeIf(const type::Unit* unit,
                                                       const std::vector<std::string_view>& features) {
    auto flags = hilti::util::toVector(
        features | std::views::transform([&](const auto& feature) { return featureConstant(unit, feature); }));


    auto* cond = std::accumulate(++flags.begin(), flags.end(), flags.front(),
                                 [this](const auto& a, const auto& b) { return builder()->expressionLogicalOr(a, b); });

    return builder()->addIf(cond);
}

QualifiedType* ParserBuilder::lookAheadType() const {
    return builder()->qualifiedType(builder()->typeSignedInteger(64), hilti::Constness::Mutable);
}

hilti::Expression* ParserBuilder::featureConstant(const type::Unit* unit, std::string_view feature) {
    const auto id = hilti::util::replace(unit->canonicalID(), ":", "@");
    return builder()->id(ID(hilti::rt::fmt("::%s%%%s%%%s", HILTI_INTERNAL_ID("feat"), id, feature)));
}

Expression* ParserBuilder::evaluateAttributeExpression(const hilti::Attribute* attr, const std::string& prefix) {
    Expression* attr_expr = *attr->valueAsExpression();

    // Temporaries are unnecessary for constants.
    if ( attr_expr->isA<hilti::expression::Ctor>() && attr_expr->isConstant() )
        return attr_expr;

    Expression* result = builder()->addTmp(prefix, attr_expr);
    result->setMeta(attr_expr->meta());
    return result;
}
