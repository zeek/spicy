// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <variant>

#include <hilti/ast/ast-context.h>
#include <hilti/ast/builder/builder.h>
#include <hilti/ast/declarations/function.h>
#include <hilti/ast/declarations/module.h>
#include <hilti/ast/statements/declaration.h>
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

    // Read temporaries must keep the field's location on the enclosing statement too. Otherwise the statement
    // inherits the unit's location and adds a redundant unit-to-field transition to each read.
    size_t reads = 0;
    for ( auto* statement : (*function)->as<::hilti::declaration::Function>()->function()->body()->statements() ) {
        auto* declaration = statement->tryAs<::hilti::statement::Declaration>();
        if ( ! declaration || declaration->declaration()->meta().location().from() != 4 )
            continue;

        ++reads;
        CHECK_EQ(statement->meta().location(), declaration->declaration()->meta().location());
    }
    CHECK_EQ(reads, 1U);
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

TEST_CASE("a borrowed unit keeps its access in the helper's parameter") {
    auto build = [](ParameterMode mode, bool writes) {
        Package package;
        auto builder = package.builder();
        auto unit = builder.createUnitDecl("Cell");
        auto field = builder.createFieldDecl(unit, "value", builder.uint8Type());
        auto unit_type = builder.unitType(unit);
        auto helper = builder.createFunction("helper", {Parameter(unit_type, mode)}, builder.voidType());
        auto helper_block = builder.createBlock(package.function(helper).root_region);
        auto place = builder.addFieldPlace(helper_block, builder.addArgument(helper, helper_block, 0), field);
        if ( writes )
            builder.addStore(helper_block, place, builder.addLoad(helper_block, place));
        else
            builder.addLoad(helper_block, place);
        builder.addReturnVoid(helper_block);

        auto parser = builder.createParserFunction(unit, builder.parserStateType(), unit_type);
        auto block = builder.createBlock(package.function(parser).root_region);
        auto state0 = builder.addArgument(parser, block, 0);
        auto read = builder.addReadInteger(block,
                                           state0,
                                           ReadIntegerPayload{.width = 8,
                                                              .signedness = Signedness::Unsigned,
                                                              .byte_order = ByteOrder::Network});
        auto state1 = builder.addTupleGet(block, read, 0);
        auto unit1 = builder.addPublishField(block,
                                             builder.addUnitCreate(block, unit),
                                             builder.addTupleGet(block, read, 1),
                                             field);
        builder.addCall(block, helper, {unit1});
        builder.addParserFinish(block, state1, unit1);
        builder.addParserRoot(unit, parser);
        REQUIRE(verify(package).empty());

        ::hilti::init();
        spicy::init();
        ::hilti::Options options;
        auto ctx = std::make_shared<::hilti::Context>(options);
        ::hilti::Builder hilti_builder(ctx->astContext());
        auto result = lower(hilti_builder, package);
        REQUIRE(std::holds_alternative<::hilti::declaration::Module*>(result));
        return std::get<::hilti::declaration::Module*>(result)->print();
    };

    // The parameter's mode, not the representation of the caller's unit, decides the access. A root unit is held
    // through a reference, so the call hands over the object that the reference names.
    auto reading = build(ParameterMode::Borrow, false);
    CHECK(reading.find("proc_0(Unit_0 arg_0)") != std::string::npos);
    CHECK(reading.find("proc_0((*v_") != std::string::npos);

    auto writing = build(ParameterMode::BorrowMut, true);
    CHECK(writing.find("proc_0(inout Unit_0 arg_0)") != std::string::npos);
    CHECK(writing.find("proc_0((*v_") != std::string::npos);
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

namespace {

// The printed HILTI module of a package that must lower.
std::string lowered(const Package& package) {
    REQUIRE(verify(package).empty());
    ::hilti::init();
    spicy::init();
    ::hilti::Options options;
    auto ctx = std::make_shared<::hilti::Context>(options);
    ::hilti::Builder builder(ctx->astContext());
    auto result = lower(builder, package);
    REQUIRE(std::holds_alternative<::hilti::declaration::Module*>(result));
    return std::get<::hilti::declaration::Module*>(result)->print();
}

} // namespace

TEST_CASE("a CFG whose arms share their tails lowers to labeled blocks and gotos") {
    // 0 -> {1, 2}, 1 -> {3, 4}, 2 -> {3, 4}: both arms reach both returns, which nested ifs cannot express.
    Package package;
    auto builder = package.builder();
    auto fn = builder.createFunction("crossing", {builder.boolType()}, builder.int64Type());
    auto region = package.function(fn).root_region;
    auto b0 = builder.createBlock(region);
    auto b1 = builder.createBlock(region);
    auto b2 = builder.createBlock(region);
    auto b3 = builder.createBlock(region);
    auto b4 = builder.createBlock(region);
    auto flag = builder.addArgument(fn, b0, 0);
    builder.addBranch(b0, flag, b1, b2);
    builder.addBranch(b1, flag, b3, b4);
    builder.addBranch(b2, flag, b3, b4);
    builder.addReturn(b3, builder.addIntConstant(b3, builder.int64Type(), 1));
    builder.addReturn(b4, builder.addIntConstant(b4, builder.int64Type(), 2));
    builder.addFunctionRoot(fn);

    auto text = lowered(package);
    CHECK(text.find("goto b3;") != std::string::npos);
    CHECK(text.find("goto b4;") != std::string::npos);
    CHECK(text.find("b3:") != std::string::npos);
    CHECK(text.find("b4:") != std::string::npos);
    // The block that follows the entry in reverse postorder needs no label: the entry falls through into it.
    CHECK((text.find("b1:") == std::string::npos) != (text.find("b2:") == std::string::npos));
}

TEST_CASE("a value used in a block other than its own is declared at function entry") {
    // Block 1 computes a value that the join reads after a diamond. A value used only in its block stays there.
    Package package;
    auto builder = package.builder();
    auto fn = builder.createFunction("hoist", {builder.boolType()}, builder.int64Type());
    auto region = package.function(fn).root_region;
    auto entry = builder.createBlock(region);
    auto b1 = builder.createBlock(region);
    auto b2 = builder.createBlock(region);
    auto b3 = builder.createBlock(region);
    auto join = builder.createBlock(region);
    auto flag = builder.addArgument(fn, entry, 0);
    builder.addJump(entry, b1);
    auto shared = builder.addIntConstant(b1, builder.int64Type(), 7);
    builder.addBranch(b1, flag, b2, b3);
    auto only_here = builder.addIntConstant(b2, builder.int64Type(), 5);
    builder.addLocalPlace(b2, only_here);
    builder.addJump(b2, join);
    builder.addJump(b3, join);
    builder.addReturn(join, shared);
    builder.addFunctionRoot(fn);

    auto text = lowered(package);
    CHECK(text.find("local int<64> v_" + std::to_string(shared.index) + ";") != std::string::npos);
    CHECK(text.find("v_" + std::to_string(shared.index) + " = 7;") != std::string::npos);
    CHECK(text.find("local int<64> v_" + std::to_string(only_here.index) + " = 5;") != std::string::npos);
}

TEST_CASE("a Phi gets its own shadow unless all its Upsilons write the same storage") {
    auto build = [](bool same) {
        Package package;
        auto builder = package.builder();
        auto fn = builder.createFunction("merge", {builder.boolType(), builder.int64Type()}, builder.int64Type());
        auto region = package.function(fn).root_region;
        auto entry = builder.createBlock(region);
        auto then_ = builder.createBlock(region);
        auto else_ = builder.createBlock(region);
        auto join = builder.createBlock(region);
        auto flag = builder.addArgument(fn, entry, 0);
        auto number = builder.addArgument(fn, entry, 1);
        builder.addBranch(entry, flag, then_, else_);
        auto phi = builder.addPhi(join, builder.int64Type());
        builder.addUpsilon(then_, same ? number : builder.addIntConstant(then_, builder.int64Type(), 1), phi);
        builder.addJump(then_, join);
        builder.addUpsilon(else_, number, phi);
        builder.addJump(else_, join);
        builder.addReturn(join, phi);
        builder.addFunctionRoot(fn);
        return std::pair{lowered(package), phi};
    };

    auto [separate, phi] = build(false);
    auto shadow = "phi_" + std::to_string(phi.index);
    CHECK(separate.find("local int<64> " + shadow + ";") != std::string::npos);
    CHECK(separate.find(shadow + " = arg_1;") != std::string::npos);
    CHECK(separate.find("v_" + std::to_string(phi.index) + " = " + shadow) != std::string::npos);

    auto [coalesced, coalesced_phi] = build(true);
    CHECK(coalesced.find("phi_") == std::string::npos);
    CHECK(coalesced.find("return arg_1;") != std::string::npos);
}

namespace {

// A root parser that reads a tag, switches on it, and publishes `value` only in case 1. With `unreachable`, case 1 is
// a block that no edge reaches, listed before the reachable default.
Package makeSwitchingParser(bool unreachable) {
    Package package;
    auto builder = package.builder();
    auto unit = builder.createUnitDecl("U");
    auto tag_field = builder.createFieldDecl(unit, "tag", builder.uint8Type());
    auto value_field = builder.createFieldDecl(unit, "value", builder.uint8Type());
    auto fn = builder.createParserFunction(unit, builder.parserStateType(), builder.unitType(unit));
    auto region = package.function(fn).root_region;
    auto entry = builder.createBlock(region);
    auto one = builder.createBlock(region);
    auto other = builder.createBlock(region);
    auto join = builder.createBlock(region);

    auto read = builder.addReadInteger(entry, builder.addArgument(fn, entry, 0), ReadIntegerPayload{.width = 8});
    auto state = builder.addTupleGet(entry, read, 0);
    auto tag = builder.addTupleGet(entry, read, 1);
    auto self = builder.addPublishField(entry, builder.addUnitCreate(entry, unit), tag, tag_field);
    auto state_phi = builder.addPhi(join, builder.parserStateType());
    auto unit_phi = builder.addPhi(join, builder.unitType(unit));
    builder.addParserFinish(join, state_phi, unit_phi);

    std::vector<SwitchCase> cases;
    if ( ! unreachable )
        cases.push_back(SwitchCase{.value = IntegerLiteral{1}, .target = one});
    builder.addSwitch(entry, tag, SwitchPayload{.cases = cases, .default_target = other});

    auto value_read = builder.addReadInteger(one, state, ReadIntegerPayload{.width = 8});
    builder.addUpsilon(one, builder.addTupleGet(one, value_read, 0), state_phi);
    builder.addUpsilon(one,
                       builder.addPublishField(one, self, builder.addTupleGet(one, value_read, 1), value_field),
                       unit_phi);
    builder.addJump(one, join);
    builder.addUpsilon(other, state, state_phi);
    builder.addUpsilon(other, self, unit_phi);
    builder.addJump(other, join);
    builder.addParserRoot(unit, fn);
    return package;
}

} // namespace

TEST_CASE("a field that one case publishes is optional storage, and one that every path publishes is not") {
    auto text = lowered(makeSwitchingParser(false));
    CHECK(text.find("uint<8> field_0;") != std::string::npos);
    CHECK(text.find("uint<8> field_1 &optional;") != std::string::npos);
    CHECK(text.find("goto ") != std::string::npos);
    CHECK(text.find("switch (") != std::string::npos);
}

TEST_CASE("unreachable blocks and their Upsilons are not lowered") {
    auto text = lowered(makeSwitchingParser(true));
    // Only the default publishes nothing, so `value` is conditional, and the unreachable case leaves no read behind.
    CHECK(text.find("field_1 &optional;") != std::string::npos);
    CHECK(text.find("unpack<uint<8>>") != std::string::npos);
}

TEST_CASE("parser read results crossing blocks hoist only their physical value storage") {
    for ( bool bytes : {false, true} ) {
        CAPTURE(bytes);
        Package package;
        auto builder = package.builder();
        auto unit = builder.createUnitDecl("CrossBlock");
        auto field = builder.createFieldDecl(unit, "value", bytes ? builder.bytesType() : builder.uint8Type());
        auto fn = builder.createParserFunction(unit, builder.parserStateType(), builder.unitType(unit));
        auto region = package.function(fn).root_region;
        auto entry = builder.createBlock(region);
        auto read_block = builder.createBlock(region);
        auto finish = builder.createBlock(region);
        auto state = builder.addArgument(fn, entry, 0);
        auto object = builder.addUnitCreate(entry, unit);
        builder.addJump(entry, read_block);
        auto read =
            bytes ?
                builder.addReadBytes(read_block, state, builder.addIntConstant(read_block, builder.uint64Type(), 2)) :
                builder.addReadInteger(read_block,
                                       state,
                                       ReadIntegerPayload{.width = 8,
                                                          .signedness = Signedness::Unsigned,
                                                          .byte_order = ByteOrder::Network});
        builder.addJump(read_block, finish);
        auto next = builder.addTupleGet(finish, read, 0);
        auto value = builder.addTupleGet(finish, read, 1);
        auto published = builder.addPublishField(finish, object, value, field);
        builder.addParserFinish(finish, next, published);
        builder.addParserRoot(unit, fn);
        auto text = lowered(package);
        auto name = "v_" + std::to_string(read.index);
        CHECK(text.find("local " + std::string(bytes ? "bytes " : "uint<8> ") + name + ";") != std::string::npos);
        CHECK(text.find("tuple<parser.state") == std::string::npos);
    }
}

TEST_CASE("a failing read returns the legacy description and its location") {
    auto sample = makeOneByte();
    auto text = lowered(sample.package);
    CHECK(text.find("string description;") != std::string::npos);
    CHECK(text.find("string location;") != std::string::npos);
    CHECK(text.find("expecting 1 bytes for unpacking value (%u byte%s available)") != std::string::npos);
    CHECK(text.find("one-byte.spicy:4:5-4:17") != std::string::npos);
    CHECK(text.find("parsing did not complete") == std::string::npos);
}
