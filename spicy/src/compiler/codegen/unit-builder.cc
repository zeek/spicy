// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <utility>

#include <hilti/ast/builder/all.h>
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
    std::vector<hilti::type::struct_::Field> fields;

    void addField(hilti::type::struct_::Field f) { fields.emplace_back(std::move(f)); }

    void operator()(const spicy::type::unit::item::Field& f, position_t p) {
        if ( ! f.parseType().isA<type::Void>() ) {
            // Create struct field.
            AttributeSet attrs({Attribute("&optional")});

            if ( auto x = AttributeSet::find(f.attributes(), "&default") )
                attrs = AttributeSet::add(attrs, *x);

            if ( f.isTransient() )
                // This field will never make it into the C++ struct. We still
                // carry it around though as that makes type inference easier at
                // times.
                attrs = AttributeSet::add(attrs, Attribute("&no-emit"));

            // We set the field's auxiliary type to the parse type, so that
            // we retain that information.
            auto nf = hilti::type::struct_::Field(f.id(), f.itemType(), f.parseType(), std::move(attrs), f.meta());
            addField(std::move(nf));
        }

        // Add hooks.
        auto addHookDeclaration = [&](bool foreach) {
            if ( auto hook_decl = cg->compileHook(unit, f.id(), {f}, foreach, false, {}, {}, {}, f.meta()) ) {
                auto nf =
                    hilti::type::struct_::Field(hook_decl->id().local(), hook_decl->function().type(), {}, f.meta());
                addField(std::move(nf));
            }
        };

        auto addHookImplementation = [&](auto& hook) {
            if ( auto hook_impl = cg->compileHook(unit, ID(*unit.typeID(), f.id()), f, hook.isForEach(), hook.isDebug(),
                                                  hook.type().parameters(), hook.body(), hook.priority(), hook.meta()) )
                cg->addDeclaration(*hook_impl);
        };

        addHookDeclaration(false);

        if ( f.isContainer() )
            addHookDeclaration(true);

        for ( auto& h : f.hooks() )
            addHookImplementation(h);
    }

    void operator()(const spicy::type::unit::item::Switch& f, const position_t /* p */) {
        if ( f.cases().empty() )
            return;

        std::set<ID> seen;

        for ( const auto& [n, c] : hilti::util::enumerate(f.cases()) ) {
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
            Node d = std::move(*x);
            d.setScope(p.node.scope());
            attrs = AttributeSet::add(attrs, Attribute("&default", std::move(d)));
        }

        if ( f.isOptional() )
            attrs = AttributeSet::add(attrs, Attribute("&optional"));

        auto nf = hilti::type::struct_::Field(f.id(), std::move(ftype), std::move(attrs), f.meta());
        addField(std::move(nf));
    }

    void operator()(const spicy::type::unit::item::Sink& s) {
        auto type = builder::typeByID("spicy_rt::Sink", s.meta());
        AttributeSet attrs({Attribute("&default", builder::new_(std::move(type))), Attribute("&internal")});

        auto nf = hilti::type::struct_::Field(s.id(), type::Sink(), std::move(attrs), s.meta());
        addField(std::move(nf));
    }

    void operator()(const spicy::type::unit::item::UnitHook& h, const position_t /* p */) {
        auto addHookImplementation = [&](const auto& hook, auto /* foreach */) {
            if ( auto hook_impl =
                     cg->compileHook(unit, ID(*unit.typeID(), h.id()), {}, false, h.hook().isDebug(),
                                     h.hook().type().parameters(), hook.body(), hook.priority(), hook.meta()) )
                cg->addDeclaration(*hook_impl);
        };

        addHookImplementation(h.hook(), AttributeSet::find(h.hook().attributes(), "foreach"));
    }
};

} // anonymous namespace

Type CodeGen::compileUnit(const type::Unit& unit, bool declare_only) {
    auto v = FieldBuilder(this, unit);

    for ( const auto& i : unit.items() )
        v.dispatch(i);

    auto add_hook = [&](std::string id, std::vector<type::function::Parameter> params) {
        if ( auto hook_decl =
                 compileHook(unit, ID(std::move(id)), {}, false, false, std::move(params), {}, {}, unit.meta()) ) {
            auto nf =
                hilti::type::struct_::Field(hook_decl->id().local(), hook_decl->function().type(), {}, unit.meta());
            v.addField(std::move(nf));
        }
    };

    add_hook("0x25_init", {});
    add_hook("0x25_done", {});
    add_hook("0x25_error", {});

    if ( unit.supportsSinks() ) {
        add_hook("0x25_gap", {builder::parameter("seq", type::UnsignedInteger(64)),
                              builder::parameter("len", type::UnsignedInteger(64))});
        add_hook("0x25_overlap", {builder::parameter("seq", type::UnsignedInteger(64)),
                                  builder::parameter("old", type::Bytes()), builder::parameter("new_", type::Bytes())});
        add_hook("0x25_skipped", {builder::parameter("seq", type::UnsignedInteger(64))});
        add_hook("0x25_undelivered",
                 {builder::parameter("seq", type::UnsignedInteger(64)), builder::parameter("data", type::Bytes())});
    }

    if ( unit.usesRandomAccess() ) {
        auto f1 = hilti::type::struct_::Field(ID("__begin"), hilti::type::Optional(hilti::type::stream::Iterator()),
                                              AttributeSet({Attribute("&internal")}));
        auto f2 = hilti::type::struct_::Field(ID("__position"), hilti::type::Optional(hilti::type::stream::Iterator()),
                                              AttributeSet({Attribute("&internal")}));
        auto f3 =
            hilti::type::struct_::Field(ID("__position_update"), hilti::type::Optional(hilti::type::stream::Iterator()),
                                        AttributeSet({Attribute("&internal")}));
        v.addField(std::move(f1));
        v.addField(std::move(f2));
        v.addField(std::move(f3));
    }

    if ( unit.supportsSinks() || unit.isFilter() ) {
        auto parser = hilti::type::struct_::Field(ID("__parser"), builder::typeByID("spicy_rt::Parser"),
                                                  AttributeSet({Attribute("&static"), Attribute("&internal")}));
        v.addField(std::move(parser));
    }

    if ( unit.supportsSinks() ) {
        auto sink = hilti::type::struct_::Field(ID("__sink"), builder::typeByID("spicy_rt::SinkState"),
                                                AttributeSet({Attribute("&internal")}));
        v.addField(std::move(sink));
    }

    if ( unit.supportsFilters() ) {
        auto filters = hilti::type::struct_::Field(ID("__filters"),
                                                   hilti::type::StrongReference(builder::typeByID("spicy_rt::Filters")),
                                                   AttributeSet({Attribute("&internal")}));
        v.addField(std::move(filters));
    }

    if ( unit.isFilter() ) {
        auto forward = hilti::type::struct_::Field(ID("__forward"),
                                                   hilti::type::WeakReference(builder::typeByID("spicy_rt::Forward")),
                                                   AttributeSet({Attribute("&internal")}));
        v.addField(std::move(forward));
    }

    auto ft = _pb.parseMethodFunctionType({}, unit.meta());
    v.addField(type::struct_::Field(type::struct_::Field("__parse_stage1", std::move(ft))));

    assert(unit.typeID());
    Type s = hilti::type::Struct(unit.parameters(), std::move(v.fields));
    s = type::setTypeID(s, *unit.typeID());
    s = _pb.addParserMethods(s.as<hilti::type::Struct>(), unit, declare_only);

    if ( unit.isPublic() || unit.isFilter() ) {
        auto builder = builder::Builder(context());
        auto description = unit.propertyItem("%description");
        auto mime_types = hilti::util::transform(unit.propertyItems("%mime-type"), [](auto p) {
            return builder::library_type_value(*p.expression(), "spicy_rt::MIMEType");
        });
        auto ports = hilti::util::transform(unit.propertyItems("%port"), [](auto p) {
            auto dir = builder::id("spicy_rt::Direction::Both");

            if ( const auto& attrs = p.attributes() ) {
                auto orig = attrs->find("&originator");
                auto resp = attrs->find("&responder");

                if ( orig && ! resp )
                    dir = builder::id("spicy_rt::Direction::Originator");

                if ( resp && ! orig )
                    dir = builder::id("spicy_rt::Direction::Responder");
            }

            return builder::library_type_value(builder::tuple({*p.expression(), dir}), "spicy_rt::ParserPort");
        });

        Expression parse1 = builder::null();
        Expression parse3 = builder::null();

        if ( unit.parameters().empty() ) {
            parse1 = _pb.parseMethodExternalOverload1(unit);
            parse3 = _pb.parseMethodExternalOverload3(unit);
        }

        auto parser =
            builder::struct_({{ID("name"), builder::string(*unit.typeID())},
                              {ID("parse1"), parse1},
                              {ID("parse2"), _pb.parseMethodExternalOverload2(unit)},
                              {ID("parse3"), parse3},
                              {ID("type_info"), builder::typeinfo(unit)},
                              {ID("description"), (description ? *description->expression() : builder::string(""))},
                              {ID("mime_types"),
                               builder::vector(builder::typeByID("spicy_rt::MIMEType"), std::move(mime_types))},
                              {ID("ports"),
                               builder::vector(builder::typeByID("spicy_rt::ParserPort"), std::move(ports))}},
                             unit.meta());

        builder.addAssign(builder::id(ID(*unit.typeID(), "__parser")), parser);

        if ( unit.isPublic() )
            builder.addExpression(
                builder::call("spicy_rt::registerParser",
                              {builder::id(ID(*unit.typeID(), "__parser")), builder::strong_reference(unit)}));

        auto register_unit =
            builder::function(ID(fmt("__register_%s", hilti::util::replace(*unit.typeID(), "::", "_"))), type::Void(),
                              {}, builder.block(), type::function::Flavor::Standard, declaration::Linkage::Init);
        addDeclaration(std::move(register_unit));
    }

    s.setOriginalNode(preserveNode(unit));
    return s;
}
