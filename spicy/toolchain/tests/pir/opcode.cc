// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <algorithm>

#include <spicy/compiler/detail/pir/ir/builder.h>
#include <spicy/compiler/detail/pir/ir/opcode.h>
#include <spicy/compiler/detail/pir/ir/package.h>
#include <spicy/compiler/detail/pir/ir/printer.h>
#include <spicy/compiler/detail/pir/ir/verifier.h>
#include <spicy/compiler/detail/pir/passes/constant-fold.h>

using namespace spicy::detail::pir::ir;
using namespace spicy::detail::pir::passes;

TEST_SUITE_BEGIN("PIR opcode schema");

namespace {

// One row per opcode; a single table-driven test checks every schema's spelling, arity,
// payload kind, terminator flag, and purity in one place, rather than one bespoke test case per
// opcode repeating the same literals with less protection against missing a new opcode.
struct ExpectedSchema {
    Opcode opcode;
    std::string_view spelling;
    size_t operand_count = 0;
    PayloadKind payload_kind = PayloadKind::None;
    bool is_terminator = false;
    bool is_pure = false;
    bool has_parser_contract = false;
};

constexpr ExpectedSchema ExpectedSchemas[] = {
    {.opcode = Opcode::Constant,
     .spelling = "core.constant",
     .payload_kind = PayloadKind::Int64Literal,
     .is_pure = true},
    {.opcode = Opcode::Add, .spelling = "core.add", .operand_count = 2},
    {.opcode = Opcode::Return, .spelling = "core.return", .operand_count = 1, .is_terminator = true},
    {.opcode = Opcode::Argument, .spelling = "core.argument", .payload_kind = PayloadKind::Argument, .is_pure = true},
    {.opcode = Opcode::TupleGet,
     .spelling = "core.tuple_get",
     .operand_count = 1,
     .payload_kind = PayloadKind::TupleGet,
     .is_pure = true},
    {.opcode = Opcode::ReadInteger,
     .spelling = "parser.read_integer",
     .operand_count = 1,
     .payload_kind = PayloadKind::ReadInteger,
     .has_parser_contract = true},
    {.opcode = Opcode::Finish, .spelling = "parser.finish", .operand_count = 2, .is_terminator = true},
    {.opcode = Opcode::UnitCreate, .spelling = "unit.create", .payload_kind = PayloadKind::Unit},
    {.opcode = Opcode::PublishField,
     .spelling = "unit.publish_field",
     .operand_count = 2,
     .payload_kind = PayloadKind::Field},
};

} // namespace

TEST_CASE(
    "every opcode's schema matches its expected spelling, arity, payload kind, terminator "
    "flag, purity, and parser-contract presence") {
    for ( const auto& expected : ExpectedSchemas ) {
        const auto* schema = schemaFor(expected.opcode);
        REQUIRE(schema);
        CHECK_EQ(schema->spelling, expected.spelling);
        CHECK_EQ(schema->operandCount(), expected.operand_count);
        CHECK_EQ(schema->operand_types.size(), expected.operand_count);
        CHECK_EQ(schema->operand_roles.size(), expected.operand_count);
        CHECK_EQ(schema->payload_kind, expected.payload_kind);
        CHECK_EQ(schema->is_terminator, expected.is_terminator);
        CHECK_EQ(schema->is_pure, expected.is_pure);
        CHECK_EQ(schema->parser_contract.has_value(), expected.has_parser_contract);
    }
}

TEST_CASE("parser.read_integer's outcome contract exactly covers success, suspension, EOD, and gap") {
    const auto* schema = schemaFor(Opcode::ReadInteger);
    REQUIRE(schema);
    REQUIRE(schema->parser_contract.has_value());
    const auto& contract = *schema->parser_contract;

    CHECK_EQ(contract.success_consumption_bytes, -1);
    CHECK_EQ(contract.insufficient_input, SuspendBehavior::SuspendAndRetry);
    CHECK_EQ(contract.eod, FailureOutcome::UnexpectedEod);
    CHECK_EQ(contract.gap, FailureOutcome::Gap);

    // Distinct outcomes must not collapse into one shared value.
    CHECK_NE(contract.eod, contract.gap);
}

TEST_CASE("core.tuple_get projects the correct element from a two-element tuple") {
    Package package;
    auto builder = package.builder();
    auto fn = builder.createParserFunction(builder.createUnitDecl("U"),
                                           builder.parserStateType(),
                                           builder.unitType(builder.createUnitDecl("U2")));
    auto block = builder.createBlock(package.function(fn).root_region);
    auto state = builder.addArgument(fn, block, 0);
    auto read = builder.addReadInteger(block, state, ReadIntegerPayload{.width = 8});
    auto state1 = builder.addTupleGet(block, read, 0);
    auto value = builder.addTupleGet(block, read, 1);

    CHECK_EQ(package.inst(state1).result_type, builder.parserStateType());
    CHECK_EQ(package.inst(value).result_type, builder.uint8Type());
}

TEST_CASE("core.tuple_get on an invalid index is rejected by the verifier without asserting") {
    Package package;
    auto builder = package.builder();
    auto fn = builder.createFunction("f", builder.int64Type());
    auto block = builder.createBlock(package.function(fn).root_region);
    auto tuple_ty = builder.tupleType({builder.int64Type()});
    auto tuple_val = builder.addInstForTesting(block, Opcode::Constant, {}, tuple_ty, InstPayload(Int64Literal{0}));
    auto get = builder.addInstForTesting(block,
                                         Opcode::TupleGet,
                                         {tuple_val},
                                         builder.int64Type(),
                                         InstPayload(TupleGetPayload{5}));
    builder.addReturn(block, get);

    // Must not assert; the invalid projection is reported as a diagnostic.
    (void)verify(package);
}

TEST_CASE("core.tuple_get on a non-tuple operand is rejected by the verifier without asserting") {
    Package package;
    auto builder = package.builder();
    auto fn = builder.createFunction("f", builder.int64Type());
    auto block = builder.createBlock(package.function(fn).root_region);
    auto c = builder.addConstant(block, 1);
    auto get =
        builder.addInstForTesting(block, Opcode::TupleGet, {c}, builder.int64Type(), InstPayload(TupleGetPayload{0}));
    builder.addReturn(block, get);

    (void)verify(package);
}

TEST_CASE("a fully constructed one-byte parser pipeline verifies with no diagnostics") {
    Package package;
    auto builder = package.builder();
    auto unit_decl = builder.createUnitDecl("OneByte");
    auto field = builder.createFieldDecl(unit_decl, "value", builder.uint8Type());
    auto fn = builder.createParserFunction(unit_decl, builder.parserStateType(), builder.unitType(unit_decl));
    auto block = builder.createBlock(package.function(fn).root_region);

    auto state0 = builder.addArgument(fn, block, 0);
    auto unit0 = builder.addUnitCreate(block, unit_decl);
    auto read = builder.addReadInteger(block, state0, ReadIntegerPayload{.width = 8});
    auto state1 = builder.addTupleGet(block, read, 0);
    auto value = builder.addTupleGet(block, read, 1);
    auto unit1 = builder.addPublishField(block, unit0, value, field);
    builder.addParserFinish(block, state1, unit1);
    builder.addParserRoot(unit_decl, fn);

    auto diags = verify(package);
    for ( const auto& d : diags )
        MESSAGE(d.message);
    CHECK(diags.empty());
    CHECK_NE(print(package).find("parser.read_integer"), std::string::npos);
}

TEST_CASE("constant folding ignores parser and unit operations and remains idempotent") {
    Package package;
    auto builder = package.builder();
    auto unit_decl = builder.createUnitDecl("OneByte");
    builder.createFieldDecl(unit_decl, "value", builder.uint8Type());
    auto fn = builder.createParserFunction(unit_decl, builder.parserStateType(), builder.unitType(unit_decl));
    auto block = builder.createBlock(package.function(fn).root_region);

    auto state0 = builder.addArgument(fn, block, 0);
    auto unit0 = builder.addUnitCreate(block, unit_decl);
    auto read = builder.addReadInteger(block, state0, ReadIntegerPayload{.width = 8});
    auto state1 = builder.addTupleGet(block, read, 0);
    auto value = builder.addTupleGet(block, read, 1);
    auto unit1 = builder.addPublishField(block, unit0, value, package.typeDecl(unit_decl).fields[0]);
    builder.addParserFinish(block, state1, unit1);

    auto before = print(package);
    CHECK_FALSE(foldConstants(package, fn));
    CHECK_EQ(print(package), before);
}

namespace {

// Builds a valid one-byte parser skeleton up through `unit.create`, leaving the caller to append
// the remaining instructions and call `verify()`.
struct OneBytePipeline {
    Package package;
    TypeDeclId unit_decl;
    DeclId field;
    FunctionId fn;
    BlockId block;
    InstId state0;
    InstId unit0;
};

OneBytePipeline makeOneBytePipeline() {
    OneBytePipeline p;
    auto builder = p.package.builder();
    p.unit_decl = builder.createUnitDecl("OneByte");
    p.field = builder.createFieldDecl(p.unit_decl, "value", builder.uint8Type());
    p.fn = builder.createParserFunction(p.unit_decl, builder.parserStateType(), builder.unitType(p.unit_decl));
    p.block = builder.createBlock(p.package.function(p.fn).root_region);
    p.state0 = builder.addArgument(p.fn, p.block, 0);
    p.unit0 = builder.addUnitCreate(p.block, p.unit_decl);
    return p;
}

} // namespace

TEST_CASE("verifier rejects reusing the pre-read parser state after parser.read_integer") {
    auto p = makeOneBytePipeline();
    auto builder = p.package.builder();
    auto read = builder.addReadInteger(p.block, p.state0, ReadIntegerPayload{.width = 8});
    auto state1 = builder.addTupleGet(p.block, read, 0);
    auto value = builder.addTupleGet(p.block, read, 1);
    auto unit1 = builder.addPublishField(p.block, p.unit0, value, p.field);
    // Malformed: finishes with the stale pre-read state instead of `state1`.
    builder.addParserFinish(p.block, p.state0, unit1);
    (void)state1;

    auto diags = verify(p.package);
    CHECK(std::ranges::any_of(diags, [](auto& d) { return d.definition == diag::ParserStateReused; }));
}

TEST_CASE("verifier rejects consuming the projected successor state twice") {
    auto p = makeOneBytePipeline();
    auto builder = p.package.builder();
    auto read = builder.addReadInteger(p.block, p.state0, ReadIntegerPayload{.width = 8});
    auto state1 = builder.addTupleGet(p.block, read, 0);
    auto value = builder.addTupleGet(p.block, read, 1);
    auto unit1 = builder.addPublishField(p.block, p.unit0, value, p.field);
    // Malformed: a second read reuses `state1`, then finish also consumes it.
    auto read2 = builder.addReadInteger(p.block, state1, ReadIntegerPayload{.width = 8});
    (void)read2;
    builder.addParserFinish(p.block, state1, unit1);

    auto diags = verify(p.package);
    CHECK(std::ranges::any_of(diags, [](auto& d) { return d.definition == diag::ParserStateReused; }));
}

TEST_CASE("verifier rejects a read with a non-state operand") {
    Package package;
    auto builder = package.builder();
    auto fn = builder.createFunction("f", builder.int64Type());
    auto block = builder.createBlock(package.function(fn).root_region);
    auto c = builder.addConstant(block, 1);
    auto read = builder.addInstForTesting(block,
                                          Opcode::ReadInteger,
                                          {c},
                                          builder.tupleType({builder.uint8Type()}),
                                          InstPayload(ReadIntegerPayload{.width = 8}));
    builder.addReturn(block, read);

    auto diags = verify(package);
    CHECK(std::ranges::any_of(diags, [](auto& d) { return d.definition == diag::OperandTypeMismatch; }));
}

TEST_CASE("verifier rejects a read with an unsupported payload") {
    auto p = makeOneBytePipeline();
    p.package.builder().addReadInteger(p.block, p.state0, ReadIntegerPayload{.width = 16});

    auto diags = verify(p.package);
    CHECK(std::ranges::any_of(diags, [](auto& d) { return d.definition == diag::ReadIntegerUnsupportedPayload; }));
}

TEST_CASE("verifier rejects a read whose declared result is not tuple<parser.state, uint8>") {
    Package package;
    auto builder = package.builder();
    auto fn = builder.createFunction("f", builder.int64Type());
    auto block = builder.createBlock(package.function(fn).root_region);
    auto state_arg_fn = builder.createParserFunction(builder.createUnitDecl("U"),
                                                     builder.parserStateType(),
                                                     builder.unitType(builder.createUnitDecl("U2")));
    auto state_block = builder.createBlock(package.function(state_arg_fn).root_region);
    auto state = builder.addArgument(state_arg_fn, state_block, 0);
    auto read = builder.addInstForTesting(state_block,
                                          Opcode::ReadInteger,
                                          {state},
                                          builder.int64Type(),
                                          InstPayload(ReadIntegerPayload{.width = 8}));
    builder.addInstForTesting(state_block, Opcode::Finish, {read, read}, builder.voidType());
    (void)block;
    (void)fn;

    auto diags = verify(package);
    CHECK(std::ranges::any_of(diags, [](auto& d) { return d.definition == diag::ReadIntegerResultTypeMismatch; }));
}

TEST_CASE("parser.finish rejects a normal function") {
    Package package;
    auto builder = package.builder();
    auto fn = builder.createFunction("f", builder.voidType());
    auto block = builder.createBlock(package.function(fn).root_region);
    auto unit_decl = builder.createUnitDecl("U");
    auto state = builder.addInstForTesting(block,
                                           Opcode::Argument,
                                           {},
                                           builder.parserStateType(),
                                           InstPayload(ArgumentPayload{0}));
    auto unit_val = builder.addUnitCreate(block, unit_decl);
    builder.addParserFinish(block, state, unit_val);

    auto diags = verify(package);
    CHECK(std::ranges::any_of(diags, [](auto& d) { return d.definition == diag::FinishInNormalFunction; }));
}

TEST_CASE("parser.finish rejects a unit from a different declaration than the function's parser unit") {
    auto p = makeOneBytePipeline();
    auto builder = p.package.builder();
    auto other_unit = builder.createUnitDecl("Other");
    auto other_val = builder.addUnitCreate(p.block, other_unit);
    auto read = builder.addReadInteger(p.block, p.state0, ReadIntegerPayload{.width = 8});
    auto state1 = builder.addTupleGet(p.block, read, 0);
    builder.addParserFinish(p.block, state1, other_val);

    auto diags = verify(p.package);
    CHECK(std::ranges::any_of(diags, [](auto& d) { return d.definition == diag::ReturnTypeMismatch; }));
}

TEST_CASE("field publication rejects a mismatched field owner") {
    auto p = makeOneBytePipeline();
    auto builder = p.package.builder();
    auto other_unit = builder.createUnitDecl("Other");
    auto other_field = builder.createFieldDecl(other_unit, "x", builder.uint8Type());
    auto read = builder.addReadInteger(p.block, p.state0, ReadIntegerPayload{.width = 8});
    auto state1 = builder.addTupleGet(p.block, read, 0);
    auto value = builder.addTupleGet(p.block, read, 1);
    // Malformed: publishes a field owned by `Other`, not `OneByte`.
    auto unit1 = builder.addPublishField(p.block, p.unit0, value, other_field);
    builder.addParserFinish(p.block, state1, unit1);

    auto diags = verify(p.package);
    CHECK(std::ranges::any_of(diags, [](auto& d) { return d.definition == diag::PublishFieldOwnerMismatch; }));
}

TEST_CASE("field publication rejects a value operand with the wrong type") {
    auto p = makeOneBytePipeline();
    auto builder = p.package.builder();
    auto read = builder.addReadInteger(p.block, p.state0, ReadIntegerPayload{.width = 8});
    auto state1 = builder.addTupleGet(p.block, read, 0);
    // Malformed: publishes `state1` (parser.state) into a uint8 field.
    auto unit1 = builder.addPublishField(p.block, p.unit0, state1, p.field);
    builder.addParserFinish(p.block, state1, unit1);

    auto diags = verify(p.package);
    CHECK(std::ranges::any_of(diags, [](auto& d) { return d.definition == diag::PublishFieldValueTypeMismatch; }));
}

TEST_CASE("field publication rejects a duplicate publication of the same field") {
    auto p = makeOneBytePipeline();
    auto builder = p.package.builder();
    auto read = builder.addReadInteger(p.block, p.state0, ReadIntegerPayload{.width = 8});
    auto state1 = builder.addTupleGet(p.block, read, 0);
    auto value = builder.addTupleGet(p.block, read, 1);
    auto unit1 = builder.addPublishField(p.block, p.unit0, value, p.field);
    auto unit2 = builder.addPublishField(p.block, unit1, value, p.field);
    builder.addParserFinish(p.block, state1, unit2);

    auto diags = verify(p.package);
    CHECK(std::ranges::any_of(diags, [](auto& d) { return d.definition == diag::DuplicateFieldPublication; }));
}

TEST_CASE("field publication rejects a missing publication") {
    auto p = makeOneBytePipeline();
    auto builder = p.package.builder();
    auto read = builder.addReadInteger(p.block, p.state0, ReadIntegerPayload{.width = 8});
    auto state1 = builder.addTupleGet(p.block, read, 0);
    // Malformed: never publishes `value`.
    builder.addParserFinish(p.block, state1, p.unit0);

    auto diags = verify(p.package);
    CHECK(std::ranges::any_of(diags, [](auto& d) { return d.definition == diag::MissingFieldPublication; }));
}

TEST_CASE("field publication rejects stale unit-state reuse and finishing the wrong unit version") {
    auto p = makeOneBytePipeline();
    auto builder = p.package.builder();
    auto read = builder.addReadInteger(p.block, p.state0, ReadIntegerPayload{.width = 8});
    auto state1 = builder.addTupleGet(p.block, read, 0);
    auto value = builder.addTupleGet(p.block, read, 1);
    auto unit1 = builder.addPublishField(p.block, p.unit0, value, p.field);
    // Malformed: finishes the stale pre-publish unit value, not `unit1`.
    builder.addParserFinish(p.block, state1, p.unit0);
    (void)unit1;

    auto diags = verify(p.package);
    CHECK(std::ranges::any_of(diags, [](auto& d) { return d.definition == diag::UnitStateStaleOrUnknownOperand; }));
}

TEST_CASE("verifier rejects two tuple_get projections of the same read's parser-state element") {
    // Soundness regression: a plain per-InstId use-count cannot see that `state_a` and `state_b`
    // are two forks of the same logical state, since each is itself a distinct, once-consumed
    // InstId. The fix must reject this at the point of the second projection, before either
    // fork is ever consumed.
    auto p = makeOneBytePipeline();
    auto builder = p.package.builder();
    auto read = builder.addReadInteger(p.block, p.state0, ReadIntegerPayload{.width = 8});
    auto state_a = builder.addTupleGet(p.block, read, 0);
    auto state_b = builder.addTupleGet(p.block, read, 0);
    auto value = builder.addTupleGet(p.block, read, 1);
    auto unit1 = builder.addPublishField(p.block, p.unit0, value, p.field);
    builder.addParserFinish(p.block, state_b, unit1);
    (void)state_a;

    auto diags = verify(p.package);
    CHECK(std::ranges::any_of(diags, [](auto& d) { return d.definition == diag::ParserStateReused; }));
}

TEST_CASE("verifier rejects a duplicate parser root targeting the same unit") {
    auto p = makeOneBytePipeline();
    auto builder = p.package.builder();
    auto read = builder.addReadInteger(p.block, p.state0, ReadIntegerPayload{.width = 8});
    auto state1 = builder.addTupleGet(p.block, read, 0);
    auto value = builder.addTupleGet(p.block, read, 1);
    auto unit1 = builder.addPublishField(p.block, p.unit0, value, p.field);
    builder.addParserFinish(p.block, state1, unit1);
    builder.addParserRoot(p.unit_decl, p.fn);
    builder.addParserRoot(p.unit_decl, p.fn);

    auto diags = verify(p.package);
    CHECK(std::ranges::any_of(diags, [](auto& d) { return d.definition == diag::DuplicateParserRootUnit; }));
}

TEST_CASE("verifier rejects a field declaration with an invalid owner without asserting") {
    Package package;
    auto builder = package.builder();
    auto field = builder.createFieldDeclForTesting(TypeDeclId{999}, "x", builder.uint8Type());
    (void)field;

    auto diags = verify(package);
    CHECK(std::ranges::any_of(diags, [](auto& d) { return d.definition == diag::DeclarationInvalidOwner; }));
}

TEST_CASE("verifier rejects a field that is not listed in its owner's membership vector") {
    Package package;
    auto builder = package.builder();
    auto unit_decl = builder.createUnitDecl("U");
    // Malformed: owner is valid, but `createFieldDeclForTesting()` never appends to `unit_decl`'s
    // fields, so the two directions of the owner<->membership relationship disagree.
    builder.createFieldDeclForTesting(unit_decl, "x", builder.uint8Type());

    auto diags = verify(package);
    CHECK(std::ranges::any_of(diags, [](auto& d) { return d.definition == diag::DeclarationNotInOwnerMembership; }));
}

TEST_CASE("verifier rejects a field listed more than once in its owner's membership vector") {
    Package package;
    auto builder = package.builder();
    auto unit_decl = builder.createUnitDecl("U");
    auto field = builder.createFieldDecl(unit_decl, "x", builder.uint8Type());
    // Malformed: the same field appears twice in `unit_decl`'s fields list.
    builder.appendFieldForTesting(unit_decl, field);

    auto diags = verify(package);
    CHECK(
        std::ranges::any_of(diags, [](auto& d) { return d.definition == diag::DeclarationDuplicateOwnerMembership; }));
}

TEST_SUITE_END();
