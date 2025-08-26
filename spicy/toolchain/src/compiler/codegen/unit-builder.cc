// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <algorithm>
#include <utility>

#include <hilti/ast/builder/all.h>
#include <hilti/ast/declarations/field.h>
#include <hilti/ast/types/bytes.h>
#include <hilti/ast/types/function.h>
#include <hilti/ast/types/name.h>
#include <hilti/ast/types/optional.h>
#include <hilti/ast/types/stream.h>
#include <hilti/ast/types/struct.h>
#include <hilti/ast/types/void.h>
#include <hilti/base/logger.h>

#include <spicy/ast/types/sink.h>
#include <spicy/ast/visitor.h>
#include <spicy/compiler/detail/codegen/codegen.h>

using namespace spicy;
using namespace spicy::detail;

using hilti::util::fmt;

namespace {

struct FieldBuilder : public visitor::PreOrder {
    FieldBuilder(CodeGen* cg, spicy::type::Unit* unit) : cg(cg), unit(unit) {}

    auto context() { return cg->context(); }
    auto builder() { return cg->builder(); }

    CodeGen* cg;
    const spicy::type::Unit* unit = nullptr;
    Declarations fields;

    void addField(hilti::declaration::Field* f) { fields.emplace_back(f); }

    void operator()(spicy::type::unit::item::Block* f) final {
        for ( const auto& i : f->allItems() )
            dispatch(i);
    }

    void operator()(spicy::type::unit::item::Field* f) final {
        // Create struct field.
        auto* attrs = builder()->attributeSet({builder()->attribute(attribute::kind::Optional)});

        if ( auto* x = f->attributes()->find(attribute::kind::Default) )
            attrs->add(context(), x);

        if ( f->isAnonymous() )
            attrs->add(context(), builder()->attribute(attribute::kind::Anonymous));

        if ( (f->isAnonymous() || f->isSkip() || f->parseType()->type()->isA<hilti::type::Void>()) &&
             ! f->itemType()->type()->isA<hilti::type::Bitfield>() )
            // This field will never make it into the C++ struct. We still
            // carry it around though as that makes type inference easier at
            // times, and also can improve error messages.
            attrs->add(context(), builder()->attribute(hilti::attribute::kind::NoEmit));

        auto* nf = builder()->declarationField(f->id(), f->itemType(), attrs, f->meta());
        addField(nf);

        // Add hooks.
        auto add_hook_declaration = [&](const auto& f, declaration::hook::Type type) {
            if ( auto hook_decl = cg->compileHook(*unit, f->id(), {f->template as<spicy::type::unit::item::Field>()},
                                                  type, false, {}, {}, {}, f->meta()) ) {
                auto nf =
                    builder()->declarationField(hook_decl->id().local(), hook_decl->function()->type(), {}, f->meta());
                addField(std::move(nf));
            }
        };

        auto add_hook_implementation = [&](auto& hook) {
            if ( auto hook_impl = cg->compileHook(*unit, ID(unit->typeID(), f->id()),
                                                  f->template as<spicy::type::unit::item::Field>(), hook->hookType(),
                                                  hook->isDebug(), hook->ftype()->parameters(), hook->body(),
                                                  hook->priority(), hook->meta()) )
                cg->addDeclaration(hook_impl);
        };

        if ( f->emitHook() ) {
            add_hook_declaration(f, declaration::hook::Type::Standard);
            add_hook_declaration(f, declaration::hook::Type::Error);

            if ( f->isContainer() )
                add_hook_declaration(f, declaration::hook::Type::ForEach);

            for ( auto* h : f->hooks() )
                add_hook_implementation(h);
        }

        if ( auto* x = f->item() )
            dispatch(x);
    }

    void operator()(spicy::type::unit::item::Switch* f) final {
        if ( f->cases().empty() )
            return;

        // We go through all items here, instead of dispatching to the cases'
        // blocks, so that we can weed out duplicate fields, which are ok for
        // switch cases if they match exactly.

        std::set<ID> seen;

        for ( const auto&& [n, c] : hilti::util::enumerate(f->cases()) ) {
            for ( const auto& i : c->block()->items() ) {
                if ( auto* f = i->tryAs<spicy::type::unit::item::Field>() ) {
                    if ( seen.contains(f->id()) )
                        // Validator ensures two fields with the same name are equivalent.
                        continue;

                    seen.insert(f->id());
                }

                dispatch(i);
            }
        }
    }

    void operator()(spicy::type::unit::item::Variable* f) final {
        AttributeSet* attrs = builder()->attributeSet();
        auto* ftype = f->itemType();

        // Create struct field.
        if ( auto* x = f->default_() )
            attrs->add(context(), builder()->attribute(attribute::kind::Default, x));

        if ( f->isOptional() )
            attrs->add(context(), builder()->attribute(attribute::kind::Optional));

        auto* nf = builder()->declarationField(f->id(), ftype, attrs, f->meta());
        addField(nf);
    }

    void operator()(spicy::type::unit::item::Sink* s) final {
        auto* type = builder()->typeName("spicy_rt::Sink", s->meta());
        auto* attrs = builder()->attributeSet({builder()->attribute(attribute::kind::Default, builder()->new_(type)),
                                               builder()->attribute(hilti::attribute::kind::Internal),
                                               builder()->attribute(hilti::attribute::kind::NeededByFeature,
                                                                    builder()->stringLiteral("supports_sinks"))});

        auto* sink = builder()->qualifiedType(builder()->typeSink(), hilti::Constness::Mutable, hilti::Side::LHS);
        auto* nf = builder()->declarationField(s->id(),
                                               builder()->qualifiedType(builder()->typeStrongReference(sink),
                                                                        hilti::Constness::Const),
                                               attrs, s->meta());
        addField(nf);
    }

    void operator()(spicy::type::unit::item::UnitHook* h) final {
        const auto& hook = h->hook();
        if ( auto* hook_impl =
                 cg->compileHook(*unit, ID(unit->typeID(), h->id()), {}, hook->hookType(), hook->isDebug(),
                                 hook->ftype()->parameters(), hook->body(), hook->priority(), h->meta()) )
            cg->addDeclaration(hook_impl);
    }
};

} // anonymous namespace

UnqualifiedType* CodeGen::compileUnit(type::Unit* unit, bool declare_only) {
    auto v = FieldBuilder(this, unit);

    for ( const auto& i : unit->items() )
        v.dispatch(i);

    auto add_hook = [&](const std::string& id, hilti::declaration::Parameters params, AttributeSet* attributes = {}) {
        if ( auto* hook_decl = compileHook(*unit, ID(id), {}, declaration::hook::Type::Standard, false,
                                           std::move(params), {}, {}, unit->meta()) ) {
            auto* nf = builder()->declarationField(hook_decl->id().local(), hook_decl->function()->type(), attributes,
                                                   unit->meta());
            v.addField(nf);
        }
    };

    if ( options().getAuxOption<bool>("spicy.track_offsets", false) ) {
        auto* u64 = builder()->qualifiedType(builder()->typeUnsignedInteger(64), hilti::Constness::Const);
        auto* opt_u64 = builder()->qualifiedType(builder()->typeOptional(u64), hilti::Constness::Const);
        auto* tuple_ =
            builder()->qualifiedType(builder()->typeTuple(QualifiedTypes{u64, opt_u64}), hilti::Constness::Const);
        auto* string = builder()->qualifiedType(builder()->typeString(), hilti::Constness::Const);
        auto* map = builder()->qualifiedType(builder()->typeMap(string, tuple_), hilti::Constness::Const);

        v.addField(builder()->declarationField(ID("__offsets"), map,
                                               builder()->attributeSet(
                                                   {builder()->attribute(hilti::attribute::kind::Internal),
                                                    builder()->attribute(hilti::attribute::kind::AlwaysEmit)})));
    }

    if ( auto* context = unit->contextType() ) {
        auto* attrs = builder()->attributeSet({builder()->attribute(hilti::attribute::kind::Internal)});
        auto* ftype = builder()->typeStrongReference(builder()->qualifiedType(context, hilti::Constness::Mutable));
        auto* f =
            builder()->declarationField(ID("__context"), builder()->qualifiedType(ftype, hilti::Constness::Mutable),
                                        attrs, unit->meta());
        v.addField(f);
    }

    add_hook("0x25_init", {});
    add_hook("0x25_done", {});
    add_hook("0x25_error", {builder()->parameter("__except", builder()->typeString())});
    add_hook("0x25_print", {});
    add_hook("0x25_finally", {});

    auto* attr_sync = builder()->attributeSet(
        {builder()->attribute(hilti::attribute::kind::NeededByFeature, builder()->stringLiteral("synchronization"))});
    add_hook("0x25_confirmed", {}, attr_sync);
    add_hook("0x25_rejected", {}, attr_sync);
    add_hook("0x25_synced", {}, attr_sync);

    if ( auto id = unit->canonicalID() ) {
        ID type_id = ID(hilti::rt::replace(id, ":", "@"));

        addDeclaration(builder()->constant(ID(fmt("__feat%%%s%%uses_offset", type_id)), builder()->bool_(true)));
        addDeclaration(builder()->constant(ID(fmt("__feat%%%s%%uses_random_access", type_id)), builder()->bool_(true)));
        addDeclaration(builder()->constant(ID(fmt("__feat%%%s%%uses_stream", type_id)), builder()->bool_(true)));
        addDeclaration(builder()->constant(ID(fmt("__feat%%%s%%uses_sync_advance", type_id)), builder()->bool_(true)));
        addDeclaration(
            builder()->constant(ID(fmt("__feat%%%s%%is_filter", type_id)), builder()->bool_(unit->isFilter())));
        addDeclaration(builder()->constant(ID(fmt("__feat%%%s%%supports_filters", type_id)), builder()->bool_(true)));
        addDeclaration(builder()->constant(ID(fmt("__feat%%%s%%supports_sinks", type_id)), builder()->bool_(true)));
        addDeclaration(builder()->constant(ID(fmt("__feat%%%s%%synchronization", type_id)), builder()->bool_(true)));
    }

    add_hook("0x25_gap", {builder()->parameter("seq", builder()->typeUnsignedInteger(64)),
                          builder()->parameter("len", builder()->typeUnsignedInteger(64))});
    add_hook("0x25_overlap", {builder()->parameter("seq", builder()->typeUnsignedInteger(64)),
                              builder()->parameter("old", builder()->typeBytes()),
                              builder()->parameter("new_", builder()->typeBytes())});
    add_hook("0x25_skipped", {builder()->parameter("seq", builder()->typeUnsignedInteger(64))});
    add_hook("0x25_undelivered", {builder()->parameter("seq", builder()->typeUnsignedInteger(64)),
                                  builder()->parameter("data", builder()->typeBytes())});

    auto* attr_uses_stream =
        builder()->attribute(hilti::attribute::kind::NeededByFeature, builder()->stringLiteral("uses_stream"));
    auto* stream =
        builder()->declarationField(ID("__stream"),
                                    builder()->qualifiedType(builder()->typeWeakReference(
                                                                 builder()->qualifiedType(builder()->typeStream(),
                                                                                          hilti::Constness::Const)),
                                                             hilti::Constness::Const),
                                    builder()->attributeSet(
                                        {builder()->attribute(hilti::attribute::kind::Internal), attr_uses_stream}));

    v.addField(stream);

    auto* attr_sync_advance = builder()->attributeSet(
        {builder()->attribute(hilti::attribute::kind::NeededByFeature, builder()->stringLiteral("uses_sync_advance"))});

    add_hook("0x25_sync_advance", {builder()->parameter("offset", builder()->typeUnsignedInteger(64))},
             attr_sync_advance);

    // Fields related to random-access functionality.
    auto* attr_uses_random_access =
        builder()->attribute(hilti::attribute::kind::NeededByFeature, builder()->stringLiteral("uses_random_access"));
    auto* iter = builder()->qualifiedType(builder()->typeStreamIterator(), hilti::Constness::Mutable);
    auto* f1 =
        builder()->declarationField(ID("__begin"), iter,
                                    builder()->attributeSet({builder()->attribute(hilti::attribute::kind::Internal),
                                                             attr_uses_random_access}));
    auto* f2 =
        builder()->declarationField(ID("__position_update"),
                                    builder()->qualifiedType(builder()->typeOptional(iter), hilti::Constness::Mutable),
                                    builder()->attributeSet({builder()->attribute(hilti::attribute::kind::Internal),
                                                             attr_uses_random_access}));
    v.addField(f1);
    v.addField(f2);

    // Fields related to offset functionality.
    auto* attr_uses_offset =
        builder()->attribute(hilti::attribute::kind::NeededByFeature, builder()->stringLiteral("uses_offset"));
    auto* f3 =
        builder()->declarationField(ID("__offset"),
                                    builder()->qualifiedType(builder()->typeUnsignedInteger(64),
                                                             hilti::Constness::Mutable),
                                    builder()->attributeSet(
                                        {builder()->attribute(hilti::attribute::kind::Internal), attr_uses_offset}));
    v.addField(f3);

    {
        auto* attrs = builder()->attributeSet({builder()->attribute(hilti::attribute::kind::Static),
                                               builder()->attribute(hilti::attribute::kind::Internal),
                                               builder()->attribute(hilti::attribute::kind::NeededByFeature,
                                                                    builder()->stringLiteral("supports_filters"))});

        if ( unit->isPublic() )
            attrs->add(context(), builder()->attribute(hilti::attribute::kind::AlwaysEmit));
        else
            attrs->add(context(), builder()->attribute(hilti::attribute::kind::NeededByFeature,
                                                       builder()->stringLiteral("supports_sinks")));

        if ( unit->isFilter() )
            attrs->add(context(), builder()->attribute(hilti::attribute::kind::NeededByFeature,
                                                       builder()->stringLiteral("is_filter")));

        auto* parser = builder()->declarationField(ID("__parser"),
                                                   builder()->qualifiedType(builder()->typeName("spicy_rt::Parser"),
                                                                            hilti::Constness::Const),
                                                   attrs);

        v.addField(parser);
    }

    {
        auto* attrs = builder()->attributeSet({builder()->attribute(hilti::attribute::kind::Internal),
                                               builder()->attribute(hilti::attribute::kind::NeededByFeature,
                                                                    builder()->stringLiteral("supports_sinks"))});

        // If the unit has a `%mime-type` property consumers can connect to it via
        // MIME type with `connect_mime_type`. In that case we need to always emit
        // the field since we cannot detect use of this type later on.
        if ( unit->propertyItem("%mime-type") )
            attrs->add(context(), builder()->attribute(hilti::attribute::kind::AlwaysEmit));

        auto* sink = builder()->declarationField(ID("__sink"),
                                                 builder()->qualifiedType(builder()->typeName("spicy_rt::SinkState"),
                                                                          hilti::Constness::Mutable),
                                                 attrs);
        v.addField(sink);
    }

    {
        auto* filters =
            builder()
                ->declarationField(ID("__filters"),
                                   builder()->qualifiedType(builder()->typeStrongReference(
                                                                builder()->qualifiedType(builder()->typeName(
                                                                                             "spicy_rt::Filters"),
                                                                                         hilti::Constness::Mutable)),
                                                            hilti::Constness::Mutable),
                                   builder()->attributeSet(
                                       {builder()->attribute(hilti::attribute::kind::Internal),
                                        builder()->attribute(hilti::attribute::kind::NeededByFeature,
                                                             builder()->stringLiteral("supports_filters"))}));
        v.addField(filters);
    }

    if ( unit->isFilter() ) {
        auto* forward =
            builder()
                ->declarationField(ID("__forward"),
                                   builder()->qualifiedType(builder()->typeWeakReference(
                                                                builder()->qualifiedType(builder()->typeName(
                                                                                             "spicy_rt::Forward"),
                                                                                         hilti::Constness::Mutable)),
                                                            hilti::Constness::Mutable),
                                   builder()->attributeSet(
                                       {builder()->attribute(hilti::attribute::kind::Internal),
                                        builder()->attribute(hilti::attribute::kind::NeededByFeature,
                                                             builder()->stringLiteral("is_filter"))}));
        v.addField(forward);
    }

    auto* ft = _pb.parseMethodFunctionType({}, unit->meta());
    v.addField(
        builder()->declarationField(ID("__parse_stage1"), builder()->qualifiedType(ft, hilti::Constness::Mutable), {}));

    if ( auto* convert = unit->attributes()->find(attribute::kind::Convert) ) {
        auto* expression = *convert->valueAsExpression();
        auto* result = builder()->qualifiedType(builder()->typeAuto(), hilti::Constness::Mutable);
        auto* ftype = builder()->typeFunction(result, {}, hilti::type::function::Flavor::Method,
                                              hilti::type::function::CallingConvention::Standard, expression->meta());

        _pb.pushBuilder();
        _pb.builder()->addReturn(expression);
        auto body = _pb.popBuilder();
        auto* function = builder()->function(ID("__convert"), ftype, body->block());
        auto* convert_ = builder()->declarationField(ID("__convert"), function, {});
        v.addField(convert_);
    }

    assert(unit->typeID());
    auto* s = builder()->typeStruct(unit->parameters(), v.fields);
    _pb.addParserMethods(s, unit, declare_only);

    if ( ! declare_only )
        _compileParserRegistration(unit->typeID(), unit->typeID(), unit);

    return s;
}

void CodeGen::compilePublicUnitAlias(hilti::declaration::Module* module, const ID& alias_id, type::Unit* unit) {
    // We create a mini parser struct here that just contains the `__parser` field for runtime registration.
    auto* attrs = builder()->attributeSet(
        {builder()->attribute(hilti::attribute::kind::Static), builder()->attribute(hilti::attribute::kind::Internal),
         builder()->attribute(hilti::attribute::kind::NeededByFeature, builder()->stringLiteral("supports_filters"))});

    auto* parser_field = builder()->declarationField(ID("__parser"),
                                                     builder()->qualifiedType(builder()->typeName("spicy_rt::Parser"),
                                                                              hilti::Constness::Mutable),
                                                     attrs);

    auto struct_id = ID(alias_id.namespace_(), "__parser_" + alias_id.local().str());
    auto* struct_decl = builder()->declarationType(struct_id.local(),
                                                   builder()->qualifiedType(builder()->typeStruct({parser_field}),
                                                                            hilti::Constness::Mutable),
                                                   hilti::declaration::Linkage::Public, unit->meta());
    module->add(context(), struct_decl);

    _compileParserRegistration(alias_id, struct_id, unit);
}

void CodeGen::_compileParserRegistration(const ID& public_id, const ID& struct_id, type::Unit* unit) {
    auto* description = unit->propertyItem("%description");
    auto mime_types =
        hilti::node::transform(unit->propertyItems("%mime-type"), [](const auto& p) { return p->expression(); });
    auto ports = hilti::node::transform(unit->propertyItems("%port"), [this](auto p) -> Expression* {
        auto dir = ID("spicy_rt::Direction::Both");

        if ( const auto& attrs = p->attributes() ) {
            auto orig = attrs->find(attribute::kind::Originator);
            auto resp = attrs->find(attribute::kind::Responder);

            if ( orig && ! resp )
                dir = ID("spicy_rt::Direction::Originator");

            else if ( resp && ! orig )
                dir = ID("spicy_rt::Direction::Responder");
        }

        return builder()->tuple({p->expression(), builder()->expressionName(dir)});
    });

    Expression* parse1 = builder()->null();
    Expression* parse3 = builder()->null();

    // Only create `parse1` and `parse3` if the unit can be default constructed.
    const auto& parameters = unit->parameters();
    if ( std::ranges::all_of(parameters, [](const auto& p) { return p->default_(); }) ) {
        parse1 = _pb.parseMethodExternalOverload1(*unit);
        parse3 = _pb.parseMethodExternalOverload3(*unit);
    }

    Expression* context_new = builder()->null();

    if ( unit->contextType() )
        context_new = _pb.contextNewFunction(*unit);

    _pb.pushBuilder();

    // Register the parser if the `is_filter` or `supports_sinks` features are
    // active; `public` units we always register (by passing an empty list of
    // features to the feature guard).
    const auto& dependent_feature_flags = unit->isPublic() ?
                                              std::vector<std::string_view>{} :
                                              std::vector<std::string_view>({"is_filter", "supports_sinks"});

    _pb.guardFeatureCode(unit, dependent_feature_flags, [&]() {
        auto* ty_mime_types = builder()->typeVector(
            builder()->qualifiedType(builder()->typeName("spicy_rt::MIMEType"), hilti::Constness::Const));
        auto* ty_ports = builder()->typeVector(
            builder()->qualifiedType(builder()->typeName("spicy_rt::ParserPort"), hilti::Constness::Const));

        auto* parser = builder()->struct_(
            {builder()->ctorStructField(ID("name"), builder()->stringLiteral(public_id.str())),
             builder()->ctorStructField(ID("is_public"), builder()->bool_(unit->isPublic())),
             builder()->ctorStructField(ID("parse1"), parse1),
             builder()->ctorStructField(ID("parse2"), _pb.parseMethodExternalOverload2(*unit)),
             builder()->ctorStructField(ID("parse3"), parse3),
             builder()->ctorStructField(ID("context_new"), context_new),
             builder()->ctorStructField(ID("type_"), builder()->id(unit->typeID())),
             // We emit different string types for generated and user-provided strings. The distinction
             // is whether they have a location, so set a dummy location so both branches behave
             // identically.
             builder()->ctorStructField(ID("description"),
                                        (description ? description->expression() : builder()->stringMutable(""))),
             builder()->ctorStructField(ID("mime_types"),
                                        builder()->vector(builder()->qualifiedType(ty_mime_types,
                                                                                   hilti::Constness::Const),
                                                          mime_types)),
             builder()->ctorStructField(ID("ports"),
                                        builder()->vector(builder()->qualifiedType(ty_ports, hilti::Constness::Const),
                                                          ports))},
            unit->meta());

        _pb.builder()->addAssign(builder()->id(ID(struct_id, "__parser")), parser);

        _pb.builder()->addExpression(
            builder()->call("spicy_rt::registerParser",
                            {builder()->id(ID(struct_id, "__parser")), builder()->scope(),
                             builder()->strongReference(builder()->qualifiedType(unit, hilti::Constness::Const))}));
    });

    auto* block = _pb.popBuilder()->block();

    auto* register_unit =
        builder()->function(ID(fmt("__register_%s_%s", hiltiModule()->uid(), public_id.local())),
                            builder()->qualifiedType(builder()->typeVoid(), hilti::Constness::Const), {}, block,
                            hilti::type::function::Flavor::Function, hilti::declaration::Linkage::Init);
    addDeclaration(register_unit);
}
