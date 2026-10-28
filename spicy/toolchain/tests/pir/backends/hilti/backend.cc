// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <variant>

#include <hilti/ast/ast-context.h>
#include <hilti/ast/builder/builder.h>
#include <hilti/ast/declarations/module.h>
#include <hilti/ast/types/struct.h>
#include <hilti/compiler/context.h>
#include <hilti/compiler/init.h>

#include <spicy/compiler/detail/pir/backends/hilti/backend.h>
#include <spicy/compiler/detail/pir/ir/builder.h>
#include <spicy/compiler/detail/pir/ir/verifier.h>
#include <spicy/compiler/init.h>

using namespace spicy::detail::pir;
using namespace spicy::detail::pir::ir;
using namespace spicy::detail::pir::backend::hilti;

namespace {

struct OneBytePackage {
    Package package;
    TypeDeclId unit;
    DeclId field;
    FunctionId function;
};

OneBytePackage makeOneByte(const std::string& name = "OneByte") {
    OneBytePackage s;
    auto builder = s.package.builder();
    auto file = s.package.sourceManager().internFile("one-byte.spicy");
    auto unit_span = s.package.sourceManager().addSpan(
        {.file = file, .begin_line = 3, .begin_column = 13, .end_line = 5, .end_column = 1});
    auto field_span = s.package.sourceManager().addSpan(
        {.file = file, .begin_line = 4, .begin_column = 5, .end_line = 4, .end_column = 17});
    s.unit = builder.createUnitDecl(name, unit_span);
    s.field = builder.createFieldDecl(s.unit, "value", builder.uint8Type(), field_span);

    auto state_type = builder.parserStateType();
    auto unit_type = builder.unitType(s.unit);
    s.function = builder.createParserFunction(s.unit, state_type, unit_type, unit_span);
    auto block = builder.createBlock(s.package.function(s.function).root_region);

    auto state0 = builder.addArgument(s.function, block, 0, unit_span);
    auto unit0 = builder.addUnitCreate(block, s.unit, unit_span);
    auto read = builder.addReadInteger(block,
                                       state0,
                                       ReadIntegerPayload{
                                           .width = 8,
                                           .signedness = Signedness::Unsigned,
                                           .byte_order = ByteOrder::Network,
                                       },
                                       field_span);
    auto state1 = builder.addTupleGet(block, read, 0, field_span);
    auto value = builder.addTupleGet(block, read, 1, field_span);
    auto unit1 = builder.addPublishField(block, unit0, value, s.field, field_span);
    builder.addParserFinish(block, state1, unit1, unit_span);

    builder.addParserRoot(s.unit, s.function);
    return s;
}

} // namespace

TEST_SUITE_BEGIN("PIR HILTI backend lowering");

TEST_CASE("the canonical one-byte package lowers to a detached module") {
    auto sample = makeOneByte();
    REQUIRE(verify(sample.package).empty());

    ::hilti::init();
    spicy::init();

    ::hilti::Options options;
    auto ctx = std::make_shared<::hilti::Context>(options);
    ::hilti::Builder builder(ctx->astContext());

    auto result = lower(builder, sample.package);
    REQUIRE(std::holds_alternative<::hilti::declaration::Module*>(result));

    auto* module = std::get<::hilti::declaration::Module*>(result);
    REQUIRE(module);
    CHECK_EQ(module->uid().id.str(), "__spicy_pir_backend");

    auto text = module->print();
    CHECK(text.find("Unit_0") != std::string::npos);
    CHECK(text.find("field_0") != std::string::npos);
    CHECK(text.find("ParseResult_0") != std::string::npos);
    CHECK(text.find("OutcomeKind") != std::string::npos);
    CHECK(text.find("parse_root_0") != std::string::npos);
    CHECK(text.find("optional<uint<8>>") == std::string::npos);
    CHECK(text.find("waitForInputOrEod") != std::string::npos);
    CHECK(text.find("MissingData") != std::string::npos);
    CHECK(text.find("advance_to_next_data") != std::string::npos);
    CHECK(text.find("trim") == std::string::npos);

    auto declarations = module->declarations();
    auto unit = std::ranges::find_if(declarations, [](auto* d) { return d->id() == ::hilti::ID("Unit_0"); });
    REQUIRE(unit != declarations.end());
    CHECK_EQ((*unit)->meta().location().file(), "one-byte.spicy");
    CHECK_EQ((*unit)->meta().location().from(), 3);

    auto fields = (*unit)->as<::hilti::declaration::Type>()->type()->type()->as<::hilti::type::Struct>()->fields();
    REQUIRE_EQ(fields.size(), 1U);
    CHECK_EQ(fields[0]->meta().location().file(), "one-byte.spicy");
    CHECK_EQ(fields[0]->meta().location().from(), 4);

    auto function = std::ranges::find_if(declarations, [](auto* d) { return d->id() == ::hilti::ID("parse_root_0"); });
    REQUIRE(function != declarations.end());
    CHECK_EQ((*function)->meta().location().file(), "one-byte.spicy");
    CHECK_EQ((*function)->meta().location().from(), 3);
}

TEST_CASE("an unsupported package lowers to Unsupported and constructs nothing") {
    Package package;
    auto pir_builder = package.builder();
    pir_builder.createFunction("free", pir_builder.voidType());

    ::hilti::init();
    spicy::init();

    ::hilti::Options options;
    auto ctx = std::make_shared<::hilti::Context>(options);
    ::hilti::Builder builder(ctx->astContext());

    auto result = lower(builder, package);
    REQUIRE(std::holds_alternative<Unsupported>(result));
    CHECK_FALSE(std::get<Unsupported>(result).features.empty());
}

TEST_CASE("a bound accessor lowers to the target's scope expression without a declaration") {
    Package package;
    auto pir_builder = package.builder();
    auto accessor = pir_builder.createTargetForeignFunction("linked_artifact_scope", {}, pir_builder.uint64Type());
    auto fn = pir_builder.createFunction("scope_user", pir_builder.uint64Type());
    auto block = pir_builder.createBlock(package.function(fn).root_region);
    pir_builder.addReturn(block, pir_builder.addOpaqueOp(block, accessor, {}));
    pir_builder.addFunctionRoot(fn);
    REQUIRE(verify(package).empty());

    ::hilti::init();
    spicy::init();

    ::hilti::Options options;
    auto ctx = std::make_shared<::hilti::Context>(options);
    ::hilti::Builder builder(ctx->astContext());

    // Nothing but a binding implements a function that the target provides, so the package cannot lower without one.
    CHECK(std::holds_alternative<Unsupported>(lower(builder, package)));

    auto bound = lower(builder, package, {{.function = accessor, .kind = TargetBindingKind::LinkedArtifactScope}});
    REQUIRE(std::holds_alternative<::hilti::declaration::Module*>(bound));
    auto text = std::get<::hilti::declaration::Module*>(bound)->print();
    CHECK(text.find("foreign_0") == std::string::npos);
    CHECK(text.find("$scope") != std::string::npos);

    // A binding for a function that is not target-provided, or for no function at all, lowers nothing.
    CHECK(std::holds_alternative<Unsupported>(
        lower(builder, package, {{.function = ForeignFunctionId{3}, .kind = TargetBindingKind::LinkedArtifactScope}})));

    Package native;
    auto native_builder = native.builder();
    auto symbol = native_builder.createForeignFunction("symbol", "::symbol", {}, native_builder.uint64Type());
    auto native_fn = native_builder.createFunction("native_user", native_builder.uint64Type());
    auto native_block = native_builder.createBlock(native.function(native_fn).root_region);
    native_builder.addReturn(native_block, native_builder.addOpaqueOp(native_block, symbol, {}));
    native_builder.addFunctionRoot(native_fn);
    CHECK(std::holds_alternative<Unsupported>(
        lower(builder, native, {{.function = symbol, .kind = TargetBindingKind::LinkedArtifactScope}})));
}

// Byte-identical repeated lowering is checked by a separate-process btest fixture instead of a
// doctest: `hilti::declaration::module::UID` uniquifies its `.unique` name (which the printer
// includes) against a process-wide counter, so two lowerings of equivalent packages in one
// process are expected to differ in that name alone, not a real determinism gap.

TEST_SUITE_END();
