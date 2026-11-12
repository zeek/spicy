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
    {.opcode = Opcode::IntConstant,
     .spelling = "core.int_constant",
     .payload_kind = PayloadKind::IntegerLiteral,
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
    {.opcode = Opcode::OpaqueOp, .spelling = "opaque.op", .payload_kind = PayloadKind::ForeignFunction},
    {.opcode = Opcode::Convert,
     .spelling = "core.convert",
     .operand_count = 1,
     .payload_kind = PayloadKind::Conversion,
     .is_pure = true},
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
    auto tuple_val =
        builder.addInstForTesting(block, Opcode::IntConstant, {}, tuple_ty, InstPayload(IntegerLiteral{0}));
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
    auto c = builder.addIntConstant(block, builder.int64Type(), 1);
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
    CHECK(std::ranges::any_of(diags, [](auto& d) { return d.tag == "parser-state-reused"; }));
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
    CHECK(std::ranges::any_of(diags, [](auto& d) { return d.tag == "parser-state-reused"; }));
}

TEST_CASE("verifier rejects a read with a non-state operand") {
    Package package;
    auto builder = package.builder();
    auto fn = builder.createFunction("f", builder.int64Type());
    auto block = builder.createBlock(package.function(fn).root_region);
    auto c = builder.addIntConstant(block, builder.int64Type(), 1);
    auto read = builder.addInstForTesting(block,
                                          Opcode::ReadInteger,
                                          {c},
                                          builder.tupleType({builder.uint8Type()}),
                                          InstPayload(ReadIntegerPayload{.width = 8}));
    builder.addReturn(block, read);

    auto diags = verify(package);
    CHECK(std::ranges::any_of(diags, [](auto& d) { return d.tag == "operand-type-mismatch"; }));
}

TEST_CASE("verifier rejects a read with an unsupported payload") {
    auto p = makeOneBytePipeline();
    p.package.builder().addReadInteger(p.block, p.state0, ReadIntegerPayload{.width = 24});

    auto diags = verify(p.package);
    CHECK(std::ranges::any_of(diags, [](auto& d) { return d.tag == "read-integer-unsupported-payload"; }));
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
    CHECK(std::ranges::any_of(diags, [](auto& d) { return d.tag == "read-integer-result-type-mismatch"; }));
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
    CHECK(std::ranges::any_of(diags, [](auto& d) { return d.tag == "finish-in-normal-function"; }));
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
    CHECK(std::ranges::any_of(diags, [](auto& d) { return d.tag == "return-type-mismatch"; }));
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
    CHECK(std::ranges::any_of(diags, [](auto& d) { return d.tag == "publish-field-owner-mismatch"; }));
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
    CHECK(std::ranges::any_of(diags, [](auto& d) { return d.tag == "publish-field-value-type-mismatch"; }));
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
    CHECK(std::ranges::any_of(diags, [](auto& d) { return d.tag == "duplicate-field-publication"; }));
}

TEST_CASE("field publication rejects a missing publication") {
    auto p = makeOneBytePipeline();
    auto builder = p.package.builder();
    auto read = builder.addReadInteger(p.block, p.state0, ReadIntegerPayload{.width = 8});
    auto state1 = builder.addTupleGet(p.block, read, 0);
    // Malformed: never publishes `value`.
    builder.addParserFinish(p.block, state1, p.unit0);

    auto diags = verify(p.package);
    CHECK(std::ranges::any_of(diags, [](auto& d) { return d.tag == "missing-field-publication"; }));
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
    CHECK(std::ranges::any_of(diags, [](auto& d) { return d.tag == "unit-state-stale-or-unknown-operand"; }));
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
    CHECK(std::ranges::any_of(diags, [](auto& d) { return d.tag == "parser-state-reused"; }));
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
    CHECK(std::ranges::any_of(diags, [](auto& d) { return d.tag == "duplicate-parser-root-unit"; }));
}

TEST_CASE("verifier rejects a field declaration with an invalid owner without asserting") {
    Package package;
    auto builder = package.builder();
    auto field = builder.createFieldDeclForTesting(TypeDeclId{999}, "x", builder.uint8Type());
    (void)field;

    auto diags = verify(package);
    CHECK(std::ranges::any_of(diags, [](auto& d) { return d.tag == "declaration-invalid-owner"; }));
}

TEST_CASE("verifier rejects a field that is not listed in its owner's membership vector") {
    Package package;
    auto builder = package.builder();
    auto unit_decl = builder.createUnitDecl("U");
    // Malformed: owner is valid, but `createFieldDeclForTesting()` never appends to `unit_decl`'s
    // fields, so the two directions of the owner<->membership relationship disagree.
    builder.createFieldDeclForTesting(unit_decl, "x", builder.uint8Type());

    auto diags = verify(package);
    CHECK(std::ranges::any_of(diags, [](auto& d) { return d.tag == "declaration-not-in-owner-membership"; }));
}

TEST_CASE("verifier rejects a field listed more than once in its owner's membership vector") {
    Package package;
    auto builder = package.builder();
    auto unit_decl = builder.createUnitDecl("U");
    auto field = builder.createFieldDecl(unit_decl, "x", builder.uint8Type());
    // Malformed: the same field appears twice in `unit_decl`'s fields list.
    builder.appendFieldForTesting(unit_decl, field);

    auto diags = verify(package);
    CHECK(std::ranges::any_of(diags, [](auto& d) { return d.tag == "declaration-duplicate-owner-membership"; }));
}

TEST_SUITE_END();

TEST_CASE("a parser function may borrow a context place after its parser state") {
    Package package;
    auto builder = package.builder();
    auto unit = builder.createUnitDecl("U");
    auto context = builder.tupleType({builder.uint64Type(), builder.uint8Type()});
    auto fn = builder.createParserFunction(unit, builder.parserStateType(), builder.unitType(unit), {}, context);
    const auto& parameters = package.function(fn).parameters;

    REQUIRE(parameters.size() == 2);
    CHECK(parameters[1].mode == ParameterMode::BorrowMut);
    CHECK(parameters[1].type == builder.placeType(context));

    auto block = builder.createBlock(package.function(fn).root_region);
    builder.addArgument(fn, block, 0);
    builder.addArgument(fn, block, 1);

    auto diags = verify(package);
    CHECK(std::ranges::none_of(diags, [](auto& d) {
        return d.tag == "parser-function-parameter-count-mismatch" ||
               d.tag == "parser-function-parameter-type-mismatch" ||
               d.tag == "parser-function-context-parameter-mismatch";
    }));
}

TEST_CASE("a parser function's context borrow must be a place that holds a tuple") {
    // Each case builds its own package, since type identities belong to one package.
    auto verified = [](auto make_second) {
        Package package;
        auto builder = package.builder();
        auto unit = builder.createUnitDecl("U");
        auto fn =
            builder.createParserFunctionForTesting(unit,
                                                   {Parameter(builder.parserStateType()), make_second(builder, unit)},
                                                   builder.unitType(unit));
        auto block = builder.createBlock(package.function(fn).root_region);
        builder.addArgument(fn, block, 0);
        builder.addArgument(fn, block, 1);
        return verify(package);
    };
    auto rejected = [](const auto& diags) {
        return std::ranges::any_of(diags,
                                   [](auto& d) { return d.tag == "parser-function-context-parameter-mismatch"; });
    };

    // A borrowed unit is an acceptable borrow for an ordinary function, but not for a context.
    CHECK(rejected(verified([](auto& b, auto unit) { return Parameter(b.unitType(unit), ParameterMode::BorrowMut); })));
    // So is a place of something that is not a tuple, or a borrow that cannot write.
    CHECK(rejected(
        verified([](auto& b, auto) { return Parameter(b.placeType(b.uint64Type()), ParameterMode::BorrowMut); })));
    CHECK(rejected(verified(
        [](auto& b, auto) { return Parameter(b.placeType(b.tupleType({b.uint64Type()})), ParameterMode::Borrow); })));
    CHECK(! rejected(verified([](auto& b, auto) {
        return Parameter(b.placeType(b.tupleType({b.uint64Type()})), ParameterMode::BorrowMut);
    })));
}

TEST_CASE("a parser root names exactly the elements of its context tuple") {
    auto verified = [](std::vector<std::string> names) {
        Package package;
        auto builder = package.builder();
        auto unit = builder.createUnitDecl("U");
        auto fn = builder.createParserFunction(unit,
                                               builder.parserStateType(),
                                               builder.unitType(unit),
                                               {},
                                               builder.tupleType({builder.uint64Type()}));
        auto block = builder.createBlock(package.function(fn).root_region);
        builder.addArgument(fn, block, 0);
        builder.addArgument(fn, block, 1);
        builder.addParserRoot(unit, fn, "U", ContextIdentity{.name = "C", .elements = std::move(names)});
        return std::ranges::any_of(verify(package), [](auto& d) { return d.tag == "parser-root-context-mismatch"; });
    };

    CHECK(! verified({"n"}));
    CHECK(verified({}));
    CHECK(verified({"n", "m"}));
}

TEST_CASE("an integer constant must fit the width of its type") {
    for ( uint8_t width : {8, 16, 32, 64} ) {
        for ( auto signedness : {Signedness::Unsigned, Signedness::Signed} ) {
            auto verified = [&](uint64_t bits) {
                Package package;
                auto builder = package.builder();
                auto type = builder.integerType(width, signedness);
                auto fn = builder.createFunction("f", type);
                auto block = builder.createBlock(package.function(fn).root_region);
                builder.addReturn(block, builder.addIntConstant(block, type, bits));
                auto errors = verify(package);
                CHECK(std::ranges::all_of(errors, [](auto& e) { return e.tag == "int-constant-out-of-range"; }));
                return errors.empty();
            };

            CHECK(verified(0));
            CHECK(verified(truncateBits(UINT64_MAX, width)));
            if ( width < 64 )
                CHECK_FALSE(verified(uint64_t{1} << width));
        }
    }
}

TEST_CASE("a signed constant prints as its signed value") {
    Package package;
    auto builder = package.builder();
    auto i8 = builder.integerType(8, Signedness::Signed);
    auto fn = builder.createFunction("f", i8);
    auto block = builder.createBlock(package.function(fn).root_region);
    builder.addReturn(block, builder.addIntConstant(block, i8, 0xff));
    CHECK(verify(package).empty());
    CHECK_NE(print(package).find("core.int_constant -1 : int8"), std::string::npos);
}

TEST_CASE("parser.read_integer produces a value of its width and signedness") {
    for ( uint32_t width : {8, 16, 32, 64} ) {
        Package package;
        auto builder = package.builder();
        auto unit = builder.createUnitDecl("U");
        auto fn = builder.createParserFunction(unit, builder.parserStateType(), builder.unitType(unit));
        auto block = builder.createBlock(package.function(fn).root_region);
        auto state = builder.addArgument(fn, block, 0);
        auto read =
            builder.addReadInteger(block, state, ReadIntegerPayload{.width = width, .signedness = Signedness::Signed});
        CHECK_EQ(package.inst(builder.addTupleGet(block, read, 1)).result_type,
                 builder.integerType(width, Signedness::Signed));

        // A result of the other signedness does not match the payload.
        builder.addInstForTesting(block,
                                  Opcode::ReadInteger,
                                  {builder.addTupleGet(block, read, 0)},
                                  builder.tupleType(
                                      {builder.parserStateType(), builder.integerType(width, Signedness::Unsigned)}),
                                  InstPayload(ReadIntegerPayload{.width = width, .signedness = Signedness::Signed}));
        auto errors = verify(package);
        CHECK(std::ranges::any_of(errors, [](auto& e) { return e.tag == "read-integer-result-type-mismatch"; }));
    }
}

TEST_CASE("core.convert accepts exactly the operand and result types of its rule") {
    struct Case {
        IntegerType from;
        std::optional<IntegerType> to; // a bool when absent
        ConversionRule rule;
        bool valid;
    };

    const IntegerType u8{.width = 8, .signedness = Signedness::Unsigned};
    const IntegerType u16{.width = 16, .signedness = Signedness::Unsigned};
    const IntegerType i8{.width = 8, .signedness = Signedness::Signed};
    const IntegerType i16{.width = 16, .signedness = Signedness::Signed};
    const Case cases[] = {
        {.from = u8, .to = u16, .rule = ConversionRule::IntegerWiden, .valid = true},
        {.from = u8, .to = i16, .rule = ConversionRule::IntegerWiden, .valid = true},
        {.from = i8, .to = i16, .rule = ConversionRule::IntegerWiden, .valid = true},
        {.from = i8, .to = u16, .rule = ConversionRule::IntegerWiden, .valid = false},
        {.from = u16, .to = u8, .rule = ConversionRule::IntegerWiden, .valid = false},
        {.from = u8, .to = u8, .rule = ConversionRule::IntegerWiden, .valid = false},
        {.from = u8, .to = i8, .rule = ConversionRule::IntegerWiden, .valid = false},
        {.from = u8, .to = {}, .rule = ConversionRule::IntegerWiden, .valid = false},
        {.from = i8, .to = {}, .rule = ConversionRule::IntegerToBool, .valid = true},
        {.from = u8, .to = u16, .rule = ConversionRule::IntegerToBool, .valid = false},
    };

    for ( const auto& c : cases ) {
        Package package;
        auto builder = package.builder();
        auto from = builder.integerType(c.from.width, c.from.signedness);
        auto to = c.to ? builder.integerType(c.to->width, c.to->signedness) : builder.boolType();
        auto fn = builder.createFunction("f", to);
        auto block = builder.createBlock(package.function(fn).root_region);
        auto value = builder.addIntConstant(block, from, 1);
        builder.addReturn(block, builder.addConvert(block, value, to, c.rule));

        auto errors = verify(package);
        CHECK(std::ranges::all_of(errors, [](auto& e) { return e.tag == "convert-rule-mismatch"; }));
        CHECK_EQ(errors.empty(), c.valid);
    }

    // A conversion's operand must be an integer for either rule.
    Package package;
    auto builder = package.builder();
    auto fn = builder.createFunction("f", builder.boolType());
    auto block = builder.createBlock(package.function(fn).root_region);
    auto flag = builder.addBoolConstant(block, true);
    builder.addReturn(block, builder.addConvert(block, flag, builder.boolType(), ConversionRule::IntegerToBool));
    auto errors = verify(package);
    CHECK(std::ranges::any_of(errors, [](auto& e) { return e.tag == "convert-rule-mismatch"; }));
}

TEST_CASE("constant folding converts constants and merges widenings") {
    Package package;
    auto builder = package.builder();
    auto i8 = builder.integerType(8, Signedness::Signed);
    auto i32 = builder.integerType(32, Signedness::Signed);
    auto u8 = builder.uint8Type();
    auto u16 = builder.integerType(16, Signedness::Unsigned);
    auto fn = builder.createFunction("f", std::vector<Parameter>{u8}, builder.uint64Type());
    auto block = builder.createBlock(package.function(fn).root_region);
    auto arg = builder.addArgument(fn, block, 0);
    auto minus_one =
        builder.addConvert(block, builder.addIntConstant(block, i8, 0xff), i32, ConversionRule::IntegerWiden);
    auto zero = builder.addConvert(block,
                                   builder.addIntConstant(block, u8, 0),
                                   builder.boolType(),
                                   ConversionRule::IntegerToBool);
    auto narrow = builder.addConvert(block, arg, u16, ConversionRule::IntegerWiden);
    auto wide = builder.addConvert(block, narrow, builder.uint64Type(), ConversionRule::IntegerWiden);
    builder.addReturn(block, wide);

    REQUIRE(verify(package).empty());
    CHECK(foldConstants(package, fn));
    REQUIRE(verify(package).empty());
    CHECK_EQ(package.inst(minus_one).opcode, Opcode::IntConstant);
    CHECK_EQ(std::get<IntegerLiteral>(package.inst(minus_one).payload).bits, 0xffffffffU);
    CHECK_EQ(package.inst(zero).opcode, Opcode::BoolConstant);
    CHECK_FALSE(std::get<BoolLiteral>(package.inst(zero).payload).value);
    CHECK_EQ(package.inst(wide).opcode, Opcode::Convert);
    CHECK_EQ(package.inst(wide).args, std::vector<InstId>{arg});
}

namespace {

// A parser function that reads bytes of a length computed by `make_length`, then finishes.
struct BytesRead {
    Package package;
    InstId read;
};

template<typename MakeLength>
BytesRead makeBytesRead(MakeLength make_length) {
    BytesRead r;
    auto builder = r.package.builder();
    auto unit = builder.createUnitDecl("U");
    auto fn = builder.createParserFunction(unit, builder.parserStateType(), builder.unitType(unit));
    auto block = builder.createBlock(r.package.function(fn).root_region);
    auto state = builder.addArgument(fn, block, 0);
    auto self = builder.addUnitCreate(block, unit);
    r.read = builder.addReadBytes(block, state, make_length(builder, block));
    builder.addParserFinish(block, builder.addTupleGet(block, r.read, 0), self);
    builder.addParserRoot(unit, fn);
    return r;
}

} // namespace

TEST_CASE("parser.read_bytes takes a uint64 length and knows its consumption only for a constant") {
    auto constant = makeBytesRead([](Builder& b, BlockId block) { return b.addIntConstant(block, b.uint64Type(), 3); });
    REQUIRE(verify(constant.package).empty());
    auto contract = parserContractFor(constant.package, constant.package.inst(constant.read));
    REQUIRE(contract);
    CHECK_EQ(contract->success_consumption_bytes, 3);
    CHECK_EQ(contract->bound, FailureOutcome::BoundExceeded);

    auto computed = makeBytesRead([](Builder& b, BlockId block) {
        return b.addAdd(block, b.addIntConstant(block, b.uint64Type(), 1), b.addIntConstant(block, b.uint64Type(), 2));
    });
    REQUIRE(verify(computed.package).empty());
    CHECK_EQ(parserContractFor(computed.package, computed.package.inst(computed.read))->success_consumption_bytes, -1);

    auto narrow = makeBytesRead([](Builder& b, BlockId block) { return b.addIntConstant(block, b.uint8Type(), 3); });
    auto errors = verify(narrow.package);
    CHECK(std::ranges::any_of(errors, [](auto& e) { return e.tag == "read-bytes-length-type-mismatch"; }));

    auto flag = makeBytesRead([](Builder& b, BlockId block) { return b.addBoolConstant(block, true); });
    errors = verify(flag.package);
    CHECK(std::ranges::any_of(errors, [](auto& e) { return e.tag == "operand-type-mismatch"; }));
}

TEST_CASE("parser.read_integer's consumption is its width") {
    auto p = makeOneBytePipeline();
    auto read = p.package.builder().addReadInteger(p.block, p.state0, ReadIntegerPayload{.width = 32});
    CHECK_EQ(parserContractFor(p.package, p.package.inst(read))->success_consumption_bytes, 4);
    CHECK_FALSE(parserContractFor(p.package, p.package.inst(p.state0)));
}
