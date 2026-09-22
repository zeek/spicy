// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <hilti/ast/builder/builder.h>
#include <hilti/ast/declarations/module.h>
#include <hilti/base/util.h>

#include <spicy/compiler/detail/pir/backends/hilti/backend.h>

using ::hilti::util::fmt;

namespace spicy::detail::pir::backend::hilti {

namespace {

// Adds `stmt` to the block `b` is currently building. `hilti::Builder::addXxx()` helpers all do
// exactly this through `block()->_add(...)`; this is the same call for statement kinds those
// helpers don't cover (`if`, `try`).
void addStatement(::hilti::Builder& b, ::hilti::Statement* stmt) { b.block()->_add(b.context(), stmt); }

/**
 * Names one parser root's generated declarations. Entities use package-local PIR IDs for
 * identity, not source names: `Unit_<N>` and `field_<N>` are derived from the unit's/field's
 * `TypeDeclId`/`DeclId`, while `ParseResult_<i>` and `parse_root_<i>` are derived from the root's
 * position among `package.parserRoots()`.
 */
struct RootNames {
    std::string unit_type;
    std::string field;
    std::string result_type;
    std::string function;
};

RootNames namesFor(const ir::Package& package, const ir::ParserRoot& root, size_t index) {
    const auto& unit_decl = package.typeDecl(root.unit);
    return RootNames{
        .unit_type = fmt("Unit_%u", root.unit.index),
        .field = fmt("field_%u", unit_decl.fields[0].index),
        .result_type = fmt("ParseResult_%zu", index),
        .function = fmt("parse_root_%zu", index),
    };
}

/** Builds one root's `type Unit_<N> = struct { ... };` declaration. */
::hilti::Declaration* lowerUnitType(::hilti::Builder& b, const RootNames& names) {
    auto* field_type = b.qualifiedType(b.typeUnsignedInteger(8), ::hilti::Constness::Mutable);
    auto* field =
        b.declarationField(::hilti::ID(names.field), field_type, static_cast<::hilti::AttributeSet*>(nullptr));
    auto* struct_type = b.typeStruct(::hilti::Declarations{field});
    return b.declarationType(::hilti::ID(names.unit_type),
                             b.qualifiedType(struct_type, ::hilti::Constness::Const),
                             ::hilti::declaration::Linkage::Public);
}

/** Builds one root's `type ParseResult_<i> = struct { ... };` declaration. */
::hilti::Declaration* lowerResultType(::hilti::Builder& b, const RootNames& names) {
    auto* unit_ref_type = b.qualifiedType(b.typeValueReference(b.qualifiedType(b.typeName(::hilti::ID(names.unit_type)),
                                                                               ::hilti::Constness::Mutable)),
                                          ::hilti::Constness::Mutable);

    ::hilti::Declarations fields = {
        b.declarationField(::hilti::ID("kind"),
                           b.qualifiedType(b.typeName(::hilti::ID("OutcomeKind")), ::hilti::Constness::Mutable),
                           static_cast<::hilti::AttributeSet*>(nullptr)),
        b.declarationField(::hilti::ID("unit"),
                           b.qualifiedType(b.typeOptional(unit_ref_type), ::hilti::Constness::Mutable),
                           static_cast<::hilti::AttributeSet*>(nullptr)),
        b.declarationField(::hilti::ID("cursor"),
                           b.qualifiedType(b.typeStreamView(), ::hilti::Constness::Mutable),
                           static_cast<::hilti::AttributeSet*>(nullptr)),
        b.declarationField(::hilti::ID("gap_offset"),
                           b.qualifiedType(b.typeUnsignedInteger(64), ::hilti::Constness::Mutable),
                           static_cast<::hilti::AttributeSet*>(nullptr)),
        b.declarationField(::hilti::ID("gap_length"),
                           b.qualifiedType(b.typeUnsignedInteger(64), ::hilti::Constness::Mutable),
                           static_cast<::hilti::AttributeSet*>(nullptr)),
    };

    auto* struct_type = b.typeStruct(fields);
    return b.declarationType(::hilti::ID(names.result_type),
                             b.qualifiedType(struct_type, ::hilti::Constness::Const),
                             ::hilti::declaration::Linkage::Public);
}

/** Builds a `ParseResult_<i>` struct-literal expression for one of the four closed outcomes. */
::hilti::Expression* makeResult(::hilti::Builder& b,
                                const RootNames& names,
                                ::hilti::type::enum_::Label* kind,
                                ::hilti::Expression* unit, // nullptr => absent (`Null`)
                                ::hilti::Expression* cursor,
                                ::hilti::Expression* gap_offset,
                                ::hilti::Expression* gap_length) {
    ::hilti::ctor::struct_::Fields fields = {
        b.ctorStructField(::hilti::ID("kind"), b.expression(b.ctorEnum(kind))),
        b.ctorStructField(::hilti::ID("unit"), unit ? unit : b.null()),
        b.ctorStructField(::hilti::ID("cursor"), cursor),
        b.ctorStructField(::hilti::ID("gap_offset"), gap_offset),
        b.ctorStructField(::hilti::ID("gap_length"), gap_length),
    };
    return b.struct_(fields, b.qualifiedType(b.typeName(::hilti::ID(names.result_type)), ::hilti::Constness::Mutable));
}

/**
 * Builds one root's `public function extern ParseResult_<i> parse_root_<i>(...)`, lowering the
 * accepted seven-instruction block directly. Coverage already proved the block has exactly this
 * shape, so this walks it directly rather than dispatching generically per opcode.
 */
::hilti::Declaration* lowerFunction(::hilti::Builder& b,
                                    const RootNames& names,
                                    ::hilti::type::enum_::Label* success,
                                    ::hilti::type::enum_::Label* unexpected_eod,
                                    ::hilti::type::enum_::Label* gap) {
    auto* view_type = b.qualifiedType(b.typeStreamView(), ::hilti::Constness::Mutable);

    auto* data_param = b.parameter(::hilti::ID("data"),
                                   b.typeValueReference(b.qualifiedType(b.typeStream(), ::hilti::Constness::Mutable)),
                                   ::hilti::parameter::Kind::InOut);
    auto* cursor_param = b.parameter(::hilti::ID("initial_cursor"),
                                     b.typeOptional(view_type),
                                     b.optional(view_type),
                                     ::hilti::parameter::Kind::In);

    auto* body = b.statementBlock();
    ::hilti::Builder fb(b.context(), body);

    // `local view<stream> cursor = initial_cursor ? *initial_cursor : cast<view<stream>>(*data);`
    fb.addLocal(::hilti::ID("cursor"),
                view_type,
                fb.ternary(fb.id(::hilti::ID("initial_cursor")),
                           fb.deref(fb.id(::hilti::ID("initial_cursor"))),
                           fb.cast(fb.deref(fb.id(::hilti::ID("data"))), view_type)));

    // `local value_ref<Unit_i> unit_ = new Unit_i();`
    fb.addLocal(::hilti::ID("unit_"), fb.new_(fb.typeName(::hilti::ID(names.unit_type))));

    // `if ( ! spicy_rt::waitForInputOrEod(data, cursor, 1, Null) ) return <UnexpectedEod>;`
    auto* wait_call = fb.call(::hilti::ID("spicy_rt::waitForInputOrEod"),
                              {fb.id(::hilti::ID("data")), fb.id(::hilti::ID("cursor")), fb.integer(1U), fb.null()});
    auto* eod_block = b.statementBlock();
    ::hilti::Builder eod_builder(b.context(), eod_block);
    eod_builder.addReturn(makeResult(eod_builder,
                                     names,
                                     unexpected_eod,
                                     nullptr,
                                     fb.id(::hilti::ID("cursor")),
                                     eod_builder.integer(0U),
                                     eod_builder.integer(0U)));
    addStatement(fb, b.statementIf(fb.not_(wait_call), eod_block, nullptr));

    fb.addLocal(::hilti::ID("value"), b.qualifiedType(b.typeUnsignedInteger(8), ::hilti::Constness::Mutable));
    fb.addLocal(::hilti::ID("next_cursor"), view_type);

    // `try { value = *begin(cursor); next_cursor = cursor.advance(1); } catch ( MissingData ) { ... }`
    auto* try_body = b.statementBlock();
    ::hilti::Builder try_builder(b.context(), try_body);
    try_builder.addAssign(try_builder.id(::hilti::ID("value")),
                          try_builder.deref(try_builder.begin(try_builder.id(::hilti::ID("cursor")))));
    try_builder.addAssign(try_builder.id(::hilti::ID("next_cursor")),
                          try_builder.memberCall(try_builder.id(::hilti::ID("cursor")),
                                                 "advance",
                                                 {try_builder.integer(1U)}));

    auto* catch_body = b.statementBlock();
    ::hilti::Builder catch_builder(b.context(), catch_body);
    catch_builder.addLocal(::hilti::ID("after_gap"),
                           catch_builder.memberCall(catch_builder.id(::hilti::ID("cursor")),
                                                    "advance_to_next_data",
                                                    {}));
    auto* gap_offset_expr = catch_builder.memberCall(catch_builder.id(::hilti::ID("cursor")), "offset", {});
    auto* gap_end_expr = catch_builder.memberCall(catch_builder.id(::hilti::ID("after_gap")), "offset", {});
    catch_builder.addReturn(makeResult(catch_builder,
                                       names,
                                       gap,
                                       nullptr,
                                       catch_builder.id(::hilti::ID("cursor")),
                                       gap_offset_expr,
                                       catch_builder.difference(gap_end_expr, gap_offset_expr)));

    auto* catch_param =
        b.parameter(::hilti::ID("e"), b.typeName(::hilti::ID("MissingData")), ::hilti::parameter::Kind::In);
    auto* catch_clause = b.statementTryCatch(catch_param, catch_body);
    addStatement(fb, b.statementTry(try_body, ::hilti::statement::try_::Catches{catch_clause}));

    // `unit_.field_<N> = value;`
    fb.addAssign(fb.member(fb.id(::hilti::ID("unit_")), names.field), fb.id(::hilti::ID("value")));

    // `return <Success>;`
    fb.addReturn(makeResult(fb,
                            names,
                            success,
                            fb.id(::hilti::ID("unit_")),
                            fb.id(::hilti::ID("next_cursor")),
                            fb.integer(0U),
                            fb.integer(0U)));

    auto* result_type = b.qualifiedType(b.typeName(::hilti::ID(names.result_type)), ::hilti::Constness::Mutable);
    return b.function(::hilti::ID(names.function),
                      result_type,
                      ::hilti::declaration::Parameters{data_param, cursor_param},
                      body,
                      ::hilti::type::function::Flavor::Function,
                      ::hilti::declaration::Linkage::Public,
                      ::hilti::type::function::CallingConvention::Extern);
}

} // namespace

LoweringResult lower(::hilti::Builder& builder, const ir::Package& package) {
    auto features = checkCoverage(package);
    if ( ! features.empty() )
        return Unsupported{std::move(features)};

    ::hilti::Declarations decls = {builder.import("hilti"), builder.import("spicy_rt")};

    auto* outcome_kind_type = builder.typeEnum(::hilti::type::enum_::Labels{
        builder.typeEnumLabel(::hilti::ID("Success")),
        builder.typeEnumLabel(::hilti::ID("UnexpectedEod")),
        builder.typeEnumLabel(::hilti::ID("Gap")),
    });
    auto labels = outcome_kind_type->labels();
    auto* success_label = labels[0];
    auto* unexpected_eod_label = labels[1];
    auto* gap_label = labels[2];

    decls.push_back(builder.declarationType(::hilti::ID("OutcomeKind"),
                                            builder.qualifiedType(outcome_kind_type, ::hilti::Constness::Const),
                                            ::hilti::declaration::Linkage::Public));

    for ( size_t i = 0; i < package.parserRoots().size(); ++i ) {
        auto names = namesFor(package, package.parserRoots()[i], i);
        decls.push_back(lowerUnitType(builder, names));
        decls.push_back(lowerResultType(builder, names));
        decls.push_back(lowerFunction(builder, names, success_label, unexpected_eod_label, gap_label));
    }

    auto uid = ::hilti::declaration::module::UID(::hilti::ID("__spicy_pir_backend"), ".hlt", ".hlt");
    return builder.declarationModule(uid, {}, decls);
}

} // namespace spicy::detail::pir::backend::hilti
