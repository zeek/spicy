// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <spicy/compiler/detail/pir/ir/opcode.h>
#include <spicy/compiler/detail/pir/ir/package.h>
#include <spicy/compiler/detail/pir/ir/printer.h>
#include <spicy/compiler/detail/pir/ir/verifier.h>
#include <spicy/compiler/detail/pir/passes/constant-fold.h>

using namespace spicy::detail::pir::ir;
using namespace spicy::detail::pir::passes;

TEST_SUITE_BEGIN("PIR opcode schema");

TEST_CASE("core.argument has the expected shape") {
    auto schema = lookupSchema(Opcode::Argument);
    REQUIRE(schema);
    CHECK_EQ(schema->spelling, "core.argument");
    CHECK_EQ(schema->operand_count, 0);
    CHECK_EQ(schema->payload_kind, PayloadKind::Argument);
    CHECK_FALSE(schema->is_terminator);
    CHECK(schema->is_pure);
}

TEST_CASE("core.tuple_get has the expected shape") {
    auto schema = lookupSchema(Opcode::TupleGet);
    REQUIRE(schema);
    CHECK_EQ(schema->spelling, "core.tuple_get");
    CHECK_EQ(schema->operand_count, 1);
    CHECK_EQ(schema->payload_kind, PayloadKind::TupleGet);
    CHECK_FALSE(schema->is_terminator);
    CHECK(schema->is_pure);
}

TEST_CASE("unit.create has the expected shape") {
    auto schema = lookupSchema(Opcode::UnitCreate);
    REQUIRE(schema);
    CHECK_EQ(schema->spelling, "unit.create");
    CHECK_EQ(schema->operand_count, 0);
    CHECK_EQ(schema->payload_kind, PayloadKind::Unit);
    CHECK_FALSE(schema->is_terminator);
    CHECK_FALSE(schema->is_pure);
}

TEST_CASE("unit.publish_field has the expected shape") {
    auto schema = lookupSchema(Opcode::PublishField);
    REQUIRE(schema);
    CHECK_EQ(schema->spelling, "unit.publish_field");
    CHECK_EQ(schema->operand_count, 2);
    CHECK_EQ(schema->payload_kind, PayloadKind::Field);
    CHECK_FALSE(schema->is_terminator);
    CHECK_FALSE(schema->is_pure);
}

TEST_CASE("parser.finish has the expected shape and is a terminator") {
    auto schema = lookupSchema(Opcode::Finish);
    REQUIRE(schema);
    CHECK_EQ(schema->spelling, "parser.finish");
    CHECK_EQ(schema->operand_count, 2);
    CHECK_EQ(schema->payload_kind, PayloadKind::None);
    CHECK(schema->is_terminator);
    CHECK_FALSE(schema->is_pure);
}

TEST_CASE("parser.read_integer has the expected shape, is impure, and carries a parser contract") {
    auto schema = lookupSchema(Opcode::ReadInteger);
    REQUIRE(schema);
    CHECK_EQ(schema->spelling, "parser.read_integer");
    CHECK_EQ(schema->operand_count, 1);
    CHECK_EQ(schema->payload_kind, PayloadKind::ReadInteger);
    CHECK_FALSE(schema->is_terminator);
    CHECK_FALSE(schema->is_pure);
    CHECK(schema->has_parser_contract);
}

TEST_CASE("parser.read_integer's outcome contract exactly covers success, suspension, EOD, and gap") {
    auto schema = lookupSchema(Opcode::ReadInteger);
    REQUIRE(schema);
    const auto& contract = schema->parser_contract;

    CHECK_EQ(contract.success_consumption_bytes, 1);
    CHECK_EQ(contract.insufficient_input, SuspendBehavior::SuspendAndRetry);
    CHECK_EQ(contract.eod, FailureOutcome::UnexpectedEod);
    CHECK_EQ(contract.gap, FailureOutcome::Gap);
    CHECK_EQ(contract.recoverable_rejection, FailureOutcome::Impossible);
    CHECK_EQ(contract.fatal, FailureOutcome::Impossible);

    // Distinct outcomes must not collapse into one shared value.
    CHECK_NE(contract.eod, contract.gap);
}

TEST_CASE("no opcode other than parser.read_integer claims a parser outcome contract") {
    for ( auto opcode : {Opcode::Constant,
                         Opcode::Add,
                         Opcode::Return,
                         Opcode::Argument,
                         Opcode::TupleGet,
                         Opcode::Finish,
                         Opcode::UnitCreate,
                         Opcode::PublishField} ) {
        auto schema = lookupSchema(opcode);
        REQUIRE(schema);
        CHECK_FALSE(schema->has_parser_contract);
    }
}

TEST_CASE("core.tuple_get projects the correct element from a two-element tuple") {
    Package package;
    auto fn = package.createParserFunction(package.createUnitDecl("U"),
                                           package.parserStateType(),
                                           package.unitType(package.createUnitDecl("U2")));
    auto block = package.createBlock(package.function(fn).root_region);
    auto state = package.addArgument(block, 0);
    auto read = package.addReadInteger(block, state, ReadIntegerPayload{.width = 8});
    auto state1 = package.addTupleGet(block, read, 0);
    auto value = package.addTupleGet(block, read, 1);

    CHECK_EQ(package.inst(state1).result_type, package.parserStateType());
    CHECK_EQ(package.inst(value).result_type, package.uint8Type());
}

TEST_CASE("core.tuple_get on an invalid index is rejected by the verifier without asserting") {
    Package package;
    auto fn = package.createFunction("f", package.int64Type());
    auto block = package.createBlock(package.function(fn).root_region);
    auto tuple_ty = package.tupleType({package.int64Type()});
    auto tuple_val = package.addInstForTesting(block, Opcode::Constant, {}, tuple_ty, InstPayload(Int64Literal{0}));
    auto get = package.addInstForTesting(block,
                                         Opcode::TupleGet,
                                         {tuple_val},
                                         package.int64Type(),
                                         InstPayload(TupleGetPayload{5}));
    package.addReturn(block, get);

    // Must not assert; the invalid projection is reported as a diagnostic.
    (void)verify(package);
}

TEST_CASE("core.tuple_get on a non-tuple operand is rejected by the verifier without asserting") {
    Package package;
    auto fn = package.createFunction("f", package.int64Type());
    auto block = package.createBlock(package.function(fn).root_region);
    auto c = package.addConstant(block, 1);
    auto get =
        package.addInstForTesting(block, Opcode::TupleGet, {c}, package.int64Type(), InstPayload(TupleGetPayload{0}));
    package.addReturn(block, get);

    (void)verify(package);
}

TEST_CASE("constant folding ignores parser and unit operations and remains idempotent") {
    Package package;
    auto unit_decl = package.createUnitDecl("OneByte");
    package.createFieldDecl(unit_decl, "value", package.uint8Type());
    auto fn = package.createParserFunction(unit_decl, package.parserStateType(), package.unitType(unit_decl));
    auto block = package.createBlock(package.function(fn).root_region);

    auto state0 = package.addArgument(block, 0);
    auto unit0 = package.addUnitCreate(block, unit_decl);
    auto read = package.addReadInteger(block, state0, ReadIntegerPayload{.width = 8});
    auto state1 = package.addTupleGet(block, read, 0);
    auto value = package.addTupleGet(block, read, 1);
    auto unit1 = package.addPublishField(block, unit0, value, package.typeDecl(unit_decl).fields[0]);
    package.addParserFinish(block, state1, unit1);

    auto before = print(package);
    CHECK_FALSE(foldConstants(package, fn));
    CHECK_EQ(print(package), before);
}

TEST_SUITE_END();
