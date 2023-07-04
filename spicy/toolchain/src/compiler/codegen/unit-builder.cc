// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <algorithm>
#include <utility>

#include <hilti/ast/builder/all.h>
#include <hilti/ast/declarations/field.h>
#include <hilti/ast/types/bytes.h>
#include <hilti/ast/types/function.h>
#include <hilti/ast/types/optional.h>
#include <hilti/ast/types/stream.h>
#include <hilti/ast/types/struct.h>
#include <hilti/ast/types/void.h>
#include <hilti/base/logger.h>

#include <spicy/ast/detail/visitor.h>
#include <spicy/ast/types/sink.h>
#include <spicy/compiler/detail/codegen/codegen.h>

using namespace spicy;
using namespace spicy::detail;

using hilti::util::fmt;

namespace builder = hilti::builder;

namespace {

struct FieldBuilder : public hilti::visitor::PreOrder<void, FieldBuilder> {
    FieldBuilder(CodeGen* cg, const spicy::type::Unit& unit) : cg(cg), unit(unit) {}
    CodeGen* cg;
    const spicy::type::Unit& unit;
    std::vector<Declaration> fields;

    void addField(hilti::declaration::Field f) { fields.emplace_back(std::move(f)); }

    void operator()(const spicy::type::unit::item::Field& f, position_t p) {
        // Create struct field.
        AttributeSet attrs({Attribute("&optional")});

        if ( auto x = AttributeSet::find(f.attributes(), "&default") )
            attrs = AttributeSet::add(attrs, *x);

        if ( f.isAnonymous() || f.isSkip() || f.parseType().isA<type::Void>() )
            // This field will never make it into the C++ struct. We still
            // carry it around though as that makes type inference easier at
            // times, and also can improve error messages.
            attrs = AttributeSet::add(attrs, Attribute("&no-emit"));

        auto nf = hilti::declaration::Field(f.id(), f.itemType(), std::move(attrs), f.meta());
        addField(std::move(nf));

        // Add hooks.
        auto addHookDeclaration = [&](const auto& f, bool foreach) {
            if ( auto hook_decl = cg->compileHook(unit, f.id(), {f}, foreach, false, {}, {}, {}, f.meta()) ) {
                auto nf =
                    hilti::declaration::Field(hook_decl->id().local(), hook_decl->function().type(), {}, f.meta());
                addField(std::move(nf));
            }
        };

        auto addHookImplementation = [&](auto& hook) {
            if ( auto hook_impl =
                     cg->compileHook(unit, ID(*unit.id(), f.id()), f, hook.isForEach(), hook.isDebug(),
                                     hook.ftype().parameters().copy(), hook.body(), hook.priority(), hook.meta()) )
                cg->addDeclaration(*hook_impl);
        };

        if ( f.emitHook() ) {
            addHookDeclaration(f, false);

            if ( f.isContainer() )
                addHookDeclaration(f, true);

            for ( auto& h : f.hooks() )
                addHookImplementation(h);
        }

        if ( auto x = f.item() )
            dispatch(*x);
    }

    void operator()(const spicy::type::unit::item::Switch& f, const position_t /* p */) {
        if ( f.cases().empty() )
            return;

        std::set<ID> seen;

        for ( const auto&& [n, c] : hilti::util::enumerate(f.cases()) ) {
            for ( const auto& i : c.items() ) {
                if ( auto f = i.tryAs<spicy::type::unit::item::Field>() ) {
                    if ( seen.find(f->id()) != seen.end() )
                        // Validator ensures two fields with the same name are equivalent.
                        continue;

                    seen.insert(f->id());
                }

                dispatch(i);
            }
        }
    }

    void operator()(const spicy::type::unit::item::Variable& f, const position_t p) {
        std::optional<AttributeSet> attrs;
        auto ftype = f.itemType();

        // Create struct field.
        if ( auto x = f.default_() ) {
            Node d = *x;
            d.setScope(p.node.scope());
            attrs = AttributeSet::add(attrs, Attribute("&default", std::move(d)));
        }

        if ( f.isOptional() )
            attrs = AttributeSet::add(attrs, Attribute("&optional"));

        auto nf = hilti::declaration::Field(f.id(), std::move(ftype), std::move(attrs), f.meta());
        addField(std::move(nf));
    }

    void operator()(const spicy::type::unit::item::Sink& s) {
        auto type = builder::typeByID("spicy_rt::Sink", s.meta());
        AttributeSet attrs({Attribute("&default", builder::new_(std::move(type))), Attribute("&internal"),
                            Attribute("&needed-by-feature", builder::string("supports_sinks"))});

        auto nf = hilti::declaration::Field(s.id(), type::Sink(), std::move(attrs), s.meta());
        addField(std::move(nf));
    }

    void operator()(const spicy::type::unit::item::UnitHook& h, const position_t /* p */) {
        const auto& hook = h.hook();
        if ( auto hook_impl =
                 cg->compileHook(unit, ID(*unit.id(), h.id()), {}, hook.isForEach(), hook.isDebug(),
                                 hook.ftype().parameters().copy(), hook.body(), hook.priority(), h.meta()) )
            cg->addDeclaration(*hook_impl);
    }
};

} // anonymous namespace

Type CodeGen::compileUnit(const type::Unit& unit, bool declare_only) {
    auto v = FieldBuilder(this, unit);

    for ( const auto& i : unit.items() )
        v.dispatch(i);

    auto add_hook = [&](std::string id, std::vector<type::function::Parameter> params, AttributeSet attributes = {}) {
        if ( auto hook_decl =
                 compileHook(unit, ID(std::move(id)), {}, false, false, std::move(params), {}, {}, unit.meta()) ) {
            auto nf = hilti::declaration::Field(hook_decl->id().local(), hook_decl->function().type(), attributes,
                                                unit.meta());
            v.addField(std::move(nf));
        }
    };

    if ( options().getAuxOption<bool>("spicy.track_offsets", false) ) {
        v.addField(hilti::declaration::Field(ID("__offsets"),
                                             hilti::type::Vector(hilti::type::Optional(hilti::type::Tuple(
                                                 {type::UnsignedInteger(64),
                                                  hilti::type::Optional(type::UnsignedInteger(64))}))),
                                             AttributeSet({Attribute("&internal"), Attribute("&always-emit")})));
    }

    if ( auto context = unit.contextType() ) {
        auto attrs = AttributeSet({Attribute("&internal")});
        auto ftype = hilti::type::StrongReference(*context);
        auto f = hilti::declaration::Field(ID("__context"), ftype, std::move(attrs), unit.meta());
        v.addField(std::move(f));
    }

    add_hook("0x25_init", {});
    add_hook("0x25_done", {});
    add_hook("0x25_error", { builder::parameter("__except", type::String()) });
    add_hook("0x25_print", {});
    add_hook("0x25_finally", {});

    auto attr_sync = AttributeSet({Attribute("&needed-by-feature", builder::string("synchronization"))});
    add_hook("0x25_confirmed", {}, attr_sync);
    add_hook("0x25_rejected", {}, attr_sync);
    add_hook("0x25_synced", {}, attr_sync);

    if ( unit.id() ) {
        ID typeID = ID(hilti::rt::replace(*unit.id(), ":", "_"));

        addDeclaration(builder::constant(ID(fmt("__feat%%%s%%uses_random_access", typeID)), builder::bool_(true)));
        addDeclaration(builder::constant(ID(fmt("__feat%%%s%%is_filter", typeID)), builder::bool_(unit.isFilter())));
        addDeclaration(builder::constant(ID(fmt("__feat%%%s%%supports_filters", typeID)), builder::bool_(true)));
        addDeclaration(builder::constant(ID(fmt("__feat%%%s%%supports_sinks", typeID)), builder::bool_(true)));
        addDeclaration(builder::constant(ID(fmt("__feat%%%s%%synchronization", typeID)), builder::bool_(true)));
    }

    add_hook("0x25_gap", {builder::parameter("seq", type::UnsignedInteger(64)),
                          builder::parameter("len", type::UnsignedInteger(64))});
    add_hook("0x25_overlap", {builder::parameter("seq", type::UnsignedInteger(64)),
                              builder::parameter("old", type::Bytes()), builder::parameter("new_", type::Bytes())});
    add_hook("0x25_skipped", {builder::parameter("seq", type::UnsignedInteger(64))});
    add_hook("0x25_undelivered",
             {builder::parameter("seq", type::UnsignedInteger(64)), builder::parameter("data", type::Bytes())});

    // Fields related to random-access functionality.
    auto attr_random_access = Attribute("&needed-by-feature", builder::string("uses_random_access"));
    auto f1 = hilti::declaration::Field(ID("__begin"), hilti::type::Optional(hilti::type::stream::Iterator()),
                                        AttributeSet({Attribute("&internal"), attr_random_access}));
    auto f2 = hilti::declaration::Field(ID("__position"), hilti::type::Optional(hilti::type::stream::Iterator()),
                                        AttributeSet({Attribute("&internal"), attr_random_access}));
    auto f3 = hilti::declaration::Field(ID("__position_update"), hilti::type::Optional(hilti::type::stream::Iterator()),
                                        AttributeSet({Attribute("&internal"), attr_random_access}));
    v.addField(std::move(f1));
    v.addField(std::move(f2));
    v.addField(std::move(f3));

    {
        auto attrs = AttributeSet({Attribute("&static"), Attribute("&internal"),
                                   Attribute("&needed-by-feature", builder::string("supports_filters"))});

        if ( unit.isPublic() )
            attrs = AttributeSet::add(std::move(attrs), Attribute("&always-emit"));
        else
            attrs =
                AttributeSet::add(std::move(attrs), Attribute("&needed-by-feature", builder::string("supports_sinks")));

        if ( unit.isFilter() )
            attrs = AttributeSet::add(std::move(attrs), Attribute("&needed-by-feature", builder::string("is_filter")));

        auto parser =
            hilti::declaration::Field(ID("__parser"), builder::typeByID("spicy_rt::Parser"), std::move(attrs));

        v.addField(std::move(parser));
    }

    {
        auto attrs =
            AttributeSet({Attribute("&internal"), Attribute("&needed-by-feature", builder::string("supports_sinks"))});

        // If the unit has a `%mime-type` property consumers can connect to it via
        // MIME type with `connect_mime_type`. In that case we need to always emit
        // the field since we cannot detect use of this type later on.
        if ( unit.propertyItem("%mime-type") )
            attrs = AttributeSet::add(std::move(attrs), Attribute("&always-emit"));

        auto sink = hilti::declaration::Field(ID("__sink"), builder::typeByID("spicy_rt::SinkState"), attrs);
        v.addField(std::move(sink));
    }

    auto filters =
        hilti::declaration::Field(ID("__filters"), hilti::type::StrongReference(builder::typeByID("spicy_rt::Filters")),
                                  AttributeSet({Attribute("&internal"),
                                                Attribute("&needed-by-feature", builder::string("supports_filters"))}));
    v.addField(std::move(filters));

    if ( unit.isFilter() ) {
        auto forward =
            hilti::declaration::Field(ID("__forward"),
                                      hilti::type::WeakReference(builder::typeByID("spicy_rt::Forward")),
                                      AttributeSet({Attribute("&internal"),
                                                    Attribute("&needed-by-feature", builder::string("is_filter"))}));
        v.addField(std::move(forward));
    }

    auto ft = _pb.parseMethodFunctionType({}, unit.meta());
    v.addField(hilti::declaration::Field(hilti::declaration::Field("__parse_stage1", std::move(ft))));

    if ( auto convert = AttributeSet::find(unit.attributes(), "&convert") ) {
        auto expression = *convert->valueAsExpression();
        auto result = type::auto_;
        auto params = std::vector<type::function::Parameter>();
        auto ftype = type::Function(type::function::Result(std::move(result), expression.get().meta()), params,
                                    hilti::type::function::Flavor::Method, expression.get().meta());

        _pb.pushBuilder();
        _pb.builder()->addReturn(expression);
        auto body = _pb.popBuilder();
        auto function = hilti::Function(ID("__convert"), std::move(ftype), body->block());
        auto convert_ = hilti::declaration::Field(ID("__convert"), function);
        v.addField(std::move(convert_));
    }

    assert(unit.id());
    Type s = hilti::type::Struct(unit.parameters().copy(), std::move(v.fields));
    s = type::setTypeID(s, *unit.id());
    s = _pb.addParserMethods(s.as<hilti::type::Struct>(), unit, declare_only);

    auto description = unit.propertyItem("%description");
    auto mime_types =
        hilti::node::transform(unit.propertyItems("%mime-type"), [](const auto& p) { return *p.expression(); });
    auto ports = hilti::node::transform(unit.propertyItems("%port"), [](auto p) {
        auto dir = builder::id("spicy_rt::Direction::Both");

        if ( const auto& attrs = p.attributes() ) {
            auto orig = attrs->find("&originator");
            auto resp = attrs->find("&responder");

            if ( orig && ! resp )
                dir = builder::id("spicy_rt::Direction::Originator");

            else if ( resp && ! orig )
                dir = builder::id("spicy_rt::Direction::Responder");
        }

        return builder::tuple({*p.expression(), dir});
    });

    Expression parse1 = builder::null();
    Expression parse3 = builder::null();

    // Only create `parse1` and `parse3` if the unit can be default constructed.
    const auto& parameters = unit.parameters();
    if ( std::all_of(parameters.begin(), parameters.end(), [](const auto& p) { return p.default_(); }) ) {
        parse1 = _pb.parseMethodExternalOverload1(unit);
        parse3 = _pb.parseMethodExternalOverload3(unit);
    }

    Expression context_new = builder::null();

    if ( unit.contextType() )
        context_new = _pb.contextNewFunction(unit);

    _pb.pushBuilder();

    // Register the parser if the `is_filter` or `supports_sinks` features are
    // active; `public` units we always register (by passing an empty list of
    // features to the feature guard).
    const auto dependentFeatureFlags = unit.isPublic() ? std::vector<std::string_view>{} :
                                                         std::vector<std::string_view>({"is_filter", "supports_sinks"});

    _pb.guardFeatureCode(unit, dependentFeatureFlags, [&]() {
        auto parser =
            builder::struct_({{ID("name"), builder::string(*unit.id())},
                              {ID("is_public"), builder::bool_(unit.isPublic())},
                              {ID("parse1"), parse1},
                              {ID("parse2"), _pb.parseMethodExternalOverload2(unit)},
                              {ID("parse3"), parse3},
                              {ID("context_new"), context_new},
                              {ID("type_info"), builder::typeinfo(builder::id(*unit.id()))},
                              {ID("description"), (description ? *description->expression() : builder::string(""))},
                              {ID("mime_types"),
                               builder::vector(builder::typeByID("spicy_rt::MIMEType"), std::move(mime_types))},
                              {ID("ports"),
                               builder::vector(builder::typeByID("spicy_rt::ParserPort"), std::move(ports))}},
                             unit.meta());

        _pb.builder()->addAssign(builder::id(ID(*unit.id(), "__parser")), parser);

        _pb.builder()->addExpression(
            builder::call("spicy_rt::registerParser",
                          {builder::id(ID(*unit.id(), "__parser")), builder::scope(),
                           builder::strong_reference(unit)}));
    });

    auto block = _pb.popBuilder()->block();

    auto register_unit =
        builder::function(ID(fmt("__register_%s_%s", hiltiUnit()->uniqueID(), unit.id()->local())), type::void_, {},
                          std::move(block), type::function::Flavor::Standard, declaration::Linkage::Init);
    addDeclaration(std::move(register_unit));

    return s;
}
