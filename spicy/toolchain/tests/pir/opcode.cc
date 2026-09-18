// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <algorithm>

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
    size_t operand_count;
    PayloadKind payload_kind;
    bool is_terminator;
    bool is_pure;
    bool has_parser_contract;
};

constexpr ExpectedSchema kExpected[] = {
    {Opcode::Constant, "core.constant", 0, PayloadKind::Int64Literal, false, true, false},
    {Opcode::Add, "core.add", 2, PayloadKind::None, false, false, false},
    {Opcode::Return, "core.return", 1, PayloadKind::None, true, false, false},
    {Opcode::Argument, "core.argument", 0, PayloadKind::Argument, false, true, false},
    {Opcode::TupleGet, "core.tuple_get", 1, PayloadKind::TupleGet, false, true, false},
    {Opcode::ReadInteger, "parser.read_integer", 1, PayloadKind::ReadInteger, false, false, true},
    {Opcode::Finish, "parser.finish", 2, PayloadKind::None, true, false, false},
    {Opcode::UnitCreate, "unit.create", 0, PayloadKind::Unit, false, false, false},
    {Opcode::PublishField, "unit.publish_field", 2, PayloadKind::Field, false, false, false},
};

} // namespace

TEST_CASE(
    "every opcode's schema matches its expected spelling, arity, payload kind, terminator "
    "flag, purity, and parser-contract presence") {
    for ( const auto& expected : kExpected ) {
        auto* schema = schemaFor(expected.opcode);
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
    auto* schema = schemaFor(Opcode::ReadInteger);
    REQUIRE(schema);
    REQUIRE(schema->parser_contract.has_value());
    const auto& contract = *schema->parser_contract;

    CHECK_EQ(contract.success_consumption_bytes, 1);
    CHECK_EQ(contract.insufficient_input, SuspendBehavior::SuspendAndRetry);
    CHECK_EQ(contract.eod, FailureOutcome::UnexpectedEod);
    CHECK_EQ(contract.gap, FailureOutcome::Gap);

    // Distinct outcomes must not collapse into one shared value.
    CHECK_NE(contract.eod, contract.gap);
}

TEST_CASE("core.tuple_get projects the correct element from a two-element tuple") {
    Package package;
    auto fn = package.createParserFunction(package.createUnitDecl("U"),
                                           package.parserStateType(),
                                           package.unitType(package.createUnitDecl("U2")));
    auto block = package.createBlock(package.function(fn).root_region);
    auto state = package.addArgument(fn, block, 0);
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

TEST_CASE("a fully constructed one-byte parser pipeline verifies with no diagnostics") {
    Package package;
    auto unit_decl = package.createUnitDecl("OneByte");
    auto field = package.createFieldDecl(unit_decl, "value", package.uint8Type());
    auto fn = package.createParserFunction(unit_decl, package.parserStateType(), package.unitType(unit_decl));
    auto block = package.createBlock(package.function(fn).root_region);

    auto state0 = package.addArgument(fn, block, 0);
    auto unit0 = package.addUnitCreate(block, unit_decl);
    auto read = package.addReadInteger(block, state0, ReadIntegerPayload{.width = 8});
    auto state1 = package.addTupleGet(block, read, 0);
    auto value = package.addTupleGet(block, read, 1);
    auto unit1 = package.addPublishField(block, unit0, value, field);
    package.addParserFinish(block, state1, unit1);
    package.addParserRoot(unit_decl, fn);

    auto diags = verify(package);
    for ( const auto& d : diags )
        MESSAGE(d.message);
    CHECK(diags.empty());
    CHECK_NE(print(package).find("parser.read_integer"), std::string::npos);
}

TEST_CASE("constant folding ignores parser and unit operations and remains idempotent") {
    Package package;
    auto unit_decl = package.createUnitDecl("OneByte");
    package.createFieldDecl(unit_decl, "value", package.uint8Type());
    auto fn = package.createParserFunction(unit_decl, package.parserStateType(), package.unitType(unit_decl));
    auto block = package.createBlock(package.function(fn).root_region);

    auto state0 = package.addArgument(fn, block, 0);
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
    p.unit_decl = p.package.createUnitDecl("OneByte");
    p.field = p.package.createFieldDecl(p.unit_decl, "value", p.package.uint8Type());
    p.fn = p.package.createParserFunction(p.unit_decl, p.package.parserStateType(), p.package.unitType(p.unit_decl));
    p.block = p.package.createBlock(p.package.function(p.fn).root_region);
    p.state0 = p.package.addArgument(p.fn, p.block, 0);
    p.unit0 = p.package.addUnitCreate(p.block, p.unit_decl);
    return p;
}

} // namespace

TEST_CASE("verifier rejects reusing the pre-read parser state after parser.read_integer") {
    auto p = makeOneBytePipeline();
    auto read = p.package.addReadInteger(p.block, p.state0, ReadIntegerPayload{.width = 8});
    auto state1 = p.package.addTupleGet(p.block, read, 0);
    auto value = p.package.addTupleGet(p.block, read, 1);
    auto unit1 = p.package.addPublishField(p.block, p.unit0, value, p.field);
    // Malformed: finishes with the stale pre-read state instead of `state1`.
    p.package.addParserFinish(p.block, p.state0, unit1);
    (void)state1;

    auto diags = verify(p.package);
    CHECK(std::ranges::any_of(diags, [](auto& d) { return d.definition == diag::ParserStateReused; }));
}

TEST_CASE("verifier rejects consuming the projected successor state twice") {
    auto p = makeOneBytePipeline();
    auto read = p.package.addReadInteger(p.block, p.state0, ReadIntegerPayload{.width = 8});
    auto state1 = p.package.addTupleGet(p.block, read, 0);
    auto value = p.package.addTupleGet(p.block, read, 1);
    auto unit1 = p.package.addPublishField(p.block, p.unit0, value, p.field);
    // Malformed: a second read reuses `state1`, then finish also consumes it.
    auto read2 = p.package.addReadInteger(p.block, state1, ReadIntegerPayload{.width = 8});
    (void)read2;
    p.package.addParserFinish(p.block, state1, unit1);

    auto diags = verify(p.package);
    CHECK(std::ranges::any_of(diags, [](auto& d) { return d.definition == diag::ParserStateReused; }));
}

TEST_CASE("verifier rejects a read with a non-state operand") {
    Package package;
    auto fn = package.createFunction("f", package.int64Type());
    auto block = package.createBlock(package.function(fn).root_region);
    auto c = package.addConstant(block, 1);
    auto read = package.addInstForTesting(block,
                                          Opcode::ReadInteger,
                                          {c},
                                          package.tupleType({package.uint8Type()}),
                                          InstPayload(ReadIntegerPayload{.width = 8}));
    package.addReturn(block, read);

    auto diags = verify(package);
    CHECK(std::ranges::any_of(diags, [](auto& d) { return d.definition == diag::OperandTypeMismatch; }));
}

TEST_CASE("verifier rejects a read with an unsupported payload") {
    auto p = makeOneBytePipeline();
    p.package.addReadInteger(p.block, p.state0, ReadIntegerPayload{.width = 16});

    auto diags = verify(p.package);
    CHECK(std::ranges::any_of(diags, [](auto& d) { return d.definition == diag::ReadIntegerUnsupportedPayload; }));
}

TEST_CASE("verifier rejects a read whose declared result is not tuple<parser.state, uint8>") {
    Package package;
    auto fn = package.createFunction("f", package.int64Type());
    auto block = package.createBlock(package.function(fn).root_region);
    auto state_arg_fn = package.createParserFunction(package.createUnitDecl("U"),
                                                     package.parserStateType(),
                                                     package.unitType(package.createUnitDecl("U2")));
    auto state_block = package.createBlock(package.function(state_arg_fn).root_region);
    auto state = package.addArgument(state_arg_fn, state_block, 0);
    auto read = package.addInstForTesting(state_block,
                                          Opcode::ReadInteger,
                                          {state},
                                          package.int64Type(),
                                          InstPayload(ReadIntegerPayload{.width = 8}));
    package.addInstForTesting(state_block, Opcode::Finish, {read, read}, package.voidType());
    (void)block;
    (void)fn;

    auto diags = verify(package);
    CHECK(std::ranges::any_of(diags, [](auto& d) { return d.definition == diag::ReadIntegerResultTypeMismatch; }));
}

TEST_CASE("parser.finish rejects a normal function") {
    Package package;
    auto fn = package.createFunction("f", package.voidType());
    auto block = package.createBlock(package.function(fn).root_region);
    auto unit_decl = package.createUnitDecl("U");
    auto state = package.addInstForTesting(block,
                                           Opcode::Argument,
                                           {},
                                           package.parserStateType(),
                                           InstPayload(ArgumentPayload{0}));
    auto unit_val = package.addUnitCreate(block, unit_decl);
    package.addParserFinish(block, state, unit_val);

    auto diags = verify(package);
    CHECK(std::ranges::any_of(diags, [](auto& d) { return d.definition == diag::FinishInNormalFunction; }));
}

TEST_CASE("parser.finish rejects a unit from a different declaration than the function's parser unit") {
    auto p = makeOneBytePipeline();
    auto other_unit = p.package.createUnitDecl("Other");
    auto other_val = p.package.addUnitCreate(p.block, other_unit);
    auto read = p.package.addReadInteger(p.block, p.state0, ReadIntegerPayload{.width = 8});
    auto state1 = p.package.addTupleGet(p.block, read, 0);
    p.package.addParserFinish(p.block, state1, other_val);

    auto diags = verify(p.package);
    CHECK(std::ranges::any_of(diags, [](auto& d) { return d.definition == diag::ReturnTypeMismatch; }));
}

TEST_CASE("field publication rejects a mismatched field owner") {
    auto p = makeOneBytePipeline();
    auto other_unit = p.package.createUnitDecl("Other");
    auto other_field = p.package.createFieldDecl(other_unit, "x", p.package.uint8Type());
    auto read = p.package.addReadInteger(p.block, p.state0, ReadIntegerPayload{.width = 8});
    auto state1 = p.package.addTupleGet(p.block, read, 0);
    auto value = p.package.addTupleGet(p.block, read, 1);
    // Malformed: publishes a field owned by `Other`, not `OneByte`.
    auto unit1 = p.package.addPublishField(p.block, p.unit0, value, other_field);
    p.package.addParserFinish(p.block, state1, unit1);

    auto diags = verify(p.package);
    CHECK(std::ranges::any_of(diags, [](auto& d) { return d.definition == diag::PublishFieldOwnerMismatch; }));
}

TEST_CASE("field publication rejects a value operand with the wrong type") {
    auto p = makeOneBytePipeline();
    auto read = p.package.addReadInteger(p.block, p.state0, ReadIntegerPayload{.width = 8});
    auto state1 = p.package.addTupleGet(p.block, read, 0);
    // Malformed: publishes `state1` (parser.state) into a uint8 field.
    auto unit1 = p.package.addPublishField(p.block, p.unit0, state1, p.field);
    p.package.addParserFinish(p.block, state1, unit1);

    auto diags = verify(p.package);
    CHECK(std::ranges::any_of(diags, [](auto& d) { return d.definition == diag::PublishFieldValueTypeMismatch; }));
}

TEST_CASE("field publication rejects a duplicate publication of the same field") {
    auto p = makeOneBytePipeline();
    auto read = p.package.addReadInteger(p.block, p.state0, ReadIntegerPayload{.width = 8});
    auto state1 = p.package.addTupleGet(p.block, read, 0);
    auto value = p.package.addTupleGet(p.block, read, 1);
    auto unit1 = p.package.addPublishField(p.block, p.unit0, value, p.field);
    auto unit2 = p.package.addPublishField(p.block, unit1, value, p.field);
    p.package.addParserFinish(p.block, state1, unit2);

    auto diags = verify(p.package);
    CHECK(std::ranges::any_of(diags, [](auto& d) { return d.definition == diag::DuplicateFieldPublication; }));
}

TEST_CASE("field publication rejects a missing publication") {
    auto p = makeOneBytePipeline();
    auto read = p.package.addReadInteger(p.block, p.state0, ReadIntegerPayload{.width = 8});
    auto state1 = p.package.addTupleGet(p.block, read, 0);
    // Malformed: never publishes `value`.
    p.package.addParserFinish(p.block, state1, p.unit0);

    auto diags = verify(p.package);
    CHECK(std::ranges::any_of(diags, [](auto& d) { return d.definition == diag::MissingFieldPublication; }));
}

TEST_CASE("field publication rejects stale unit-state reuse and finishing the wrong unit version") {
    auto p = makeOneBytePipeline();
    auto read = p.package.addReadInteger(p.block, p.state0, ReadIntegerPayload{.width = 8});
    auto state1 = p.package.addTupleGet(p.block, read, 0);
    auto value = p.package.addTupleGet(p.block, read, 1);
    auto unit1 = p.package.addPublishField(p.block, p.unit0, value, p.field);
    // Malformed: finishes the stale pre-publish unit value, not `unit1`.
    p.package.addParserFinish(p.block, state1, p.unit0);
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
    auto read = p.package.addReadInteger(p.block, p.state0, ReadIntegerPayload{.width = 8});
    auto state_a = p.package.addTupleGet(p.block, read, 0);
    auto state_b = p.package.addTupleGet(p.block, read, 0);
    auto value = p.package.addTupleGet(p.block, read, 1);
    auto unit1 = p.package.addPublishField(p.block, p.unit0, value, p.field);
    p.package.addParserFinish(p.block, state_b, unit1);
    (void)state_a;

    auto diags = verify(p.package);
    CHECK(std::ranges::any_of(diags, [](auto& d) { return d.definition == diag::ParserStateReused; }));
}

TEST_CASE("verifier rejects a duplicate parser root targeting the same unit") {
    auto p = makeOneBytePipeline();
    auto read = p.package.addReadInteger(p.block, p.state0, ReadIntegerPayload{.width = 8});
    auto state1 = p.package.addTupleGet(p.block, read, 0);
    auto value = p.package.addTupleGet(p.block, read, 1);
    auto unit1 = p.package.addPublishField(p.block, p.unit0, value, p.field);
    p.package.addParserFinish(p.block, state1, unit1);
    p.package.addParserRoot(p.unit_decl, p.fn);
    p.package.addParserRoot(p.unit_decl, p.fn);

    auto diags = verify(p.package);
    CHECK(std::ranges::any_of(diags, [](auto& d) { return d.definition == diag::DuplicateParserRootUnit; }));
}

TEST_CASE("verifier rejects a field declaration with an invalid owner without asserting") {
    Package package;
    auto field = package.createFieldDeclForTesting(TypeDeclId{999}, "x", package.uint8Type());
    (void)field;

    auto diags = verify(package);
    CHECK(std::ranges::any_of(diags, [](auto& d) { return d.definition == diag::DeclarationInvalidOwner; }));
}

TEST_CASE("verifier rejects a field that is not listed in its owner's membership vector") {
    Package package;
    auto unit_decl = package.createUnitDecl("U");
    // Malformed: owner is valid, but `createFieldDeclForTesting()` never appends to `unit_decl`'s
    // fields, so the two directions of the owner<->membership relationship disagree.
    package.createFieldDeclForTesting(unit_decl, "x", package.uint8Type());

    auto diags = verify(package);
    CHECK(std::ranges::any_of(diags, [](auto& d) { return d.definition == diag::DeclarationNotInOwnerMembership; }));
}

TEST_CASE("verifier rejects a field listed more than once in its owner's membership vector") {
    Package package;
    auto unit_decl = package.createUnitDecl("U");
    auto field = package.createFieldDecl(unit_decl, "x", package.uint8Type());
    // Malformed: the same field appears twice in `unit_decl`'s fields list.
    package.appendFieldForTesting(unit_decl, field);

    auto diags = verify(package);
    CHECK(
        std::ranges::any_of(diags, [](auto& d) { return d.definition == diag::DeclarationDuplicateOwnerMembership; }));
}

TEST_SUITE_END();
