// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <algorithm>
#include <limits>

#include <spicy/compiler/detail/pir/ir/builder.h>
#include <spicy/compiler/detail/pir/ir/cfg.h>
#include <spicy/compiler/detail/pir/ir/package.h>
#include <spicy/compiler/detail/pir/ir/printer.h>
#include <spicy/compiler/detail/pir/ir/verifier.h>
#include <spicy/compiler/detail/pir/passes/constant-fold.h>

using namespace spicy::detail::pir::ir;
using namespace spicy::detail::pir::passes;

namespace {

bool hasDiagnostic(const std::vector<Diagnostic>& diags, const DiagnosticDefinition& def) {
    return std::ranges::any_of(diags, [&def](const Diagnostic& d) { return d.definition == def; });
}

struct Sample {
    Package package;
    InstId add;
};

Sample makeSample() {
    Sample s;
    auto builder = s.package.builder();
    auto fn = builder.createFunction("main", builder.int64Type());
    auto block = builder.createBlock(s.package.function(fn).root_region);
    auto c40 = builder.addConstant(block, 40);
    auto c2 = builder.addConstant(block, 2);
    s.add = builder.addAdd(block, c40, c2);
    builder.addReturn(block, s.add);
    return s;
}

const char* expected_initial =
    "type %0: void\n"
    "type %1: int64\n"
    "function %0 \"main\" -> int64:\n"
    "  region %0:\n"
    "    block %0:\n"
    "      %0 = core.constant 40 : int64\n"
    "      %1 = core.constant 2 : int64\n"
    "      %2 = core.add %0, %1 : int64\n"
    "      %3: core.return %2 : void\n";

const char* expected_folded =
    "type %0: void\n"
    "type %1: int64\n"
    "function %0 \"main\" -> int64:\n"
    "  region %0:\n"
    "    block %0:\n"
    "      %0 = core.constant 40 : int64\n"
    "      %1 = core.constant 2 : int64\n"
    "      %2 = core.constant 42 : int64\n"
    "      %3: core.return %2 : void\n";

} // namespace

TEST_SUITE_BEGIN("PIR core");

TEST_CASE("builders share package type identities") {
    Package package;
    auto first = package.builder();
    const auto initial_size = package.types().size();
    auto second = package.builder();
    CHECK_EQ(package.types().size(), initial_size);
    CHECK_EQ(first.voidType(), second.voidType());
    CHECK_EQ(first.int64Type(), second.int64Type());

    const auto byte = first.uint8Type();
    const auto integer = first.uint64Type();
    const auto bytes = first.bytesType();
    const auto state = first.parserStateType();
    const auto type_count = package.types().size();
    CHECK_EQ(second.uint8Type(), byte);
    CHECK_EQ(second.uint64Type(), integer);
    CHECK_EQ(second.bytesType(), bytes);
    CHECK_EQ(second.parserStateType(), state);
    CHECK_EQ(package.builder().uint8Type(), byte);
    CHECK_EQ(package.types().size(), type_count);
}

TEST_CASE("valid package verifies and prints deterministically") {
    auto sample = makeSample();
    CHECK(verify(sample.package).empty());
    CHECK_EQ(print(sample.package), expected_initial);
}

TEST_CASE("constant folding replaces add with a constant in place") {
    auto sample = makeSample();
    auto fn = FunctionId{0};

    CHECK(foldConstants(sample.package, fn));
    CHECK(verify(sample.package).empty());
    CHECK_EQ(print(sample.package), expected_folded);

    CHECK_FALSE(foldConstants(sample.package, fn));
    CHECK_EQ(print(sample.package), expected_folded);
}

TEST_CASE("constant folding declines to fold on signed overflow") {
    Package package;
    auto builder = package.builder();
    auto fn = builder.createFunction("overflow", builder.int64Type());
    auto block = builder.createBlock(package.function(fn).root_region);
    auto max = builder.addConstant(block, std::numeric_limits<int64_t>::max());
    auto one = builder.addConstant(block, 1);
    auto add = builder.addAdd(block, max, one);
    builder.addReturn(block, add);

    CHECK(verify(package).empty());
    CHECK_FALSE(foldConstants(package, fn));
    CHECK_EQ(package.inst(add).opcode, Opcode::Add);
}

TEST_CASE("constant folding safely skips a core.add with too few operands") {
    Package package;
    auto builder = package.builder();
    auto fn = builder.createFunction("bad", builder.int64Type());
    auto block = builder.createBlock(package.function(fn).root_region);
    auto c = builder.addConstant(block, 1);
    auto add = builder.addInstForTesting(block, Opcode::Add, {c}, builder.int64Type());
    builder.addReturn(block, add);

    CHECK(hasDiagnostic(verify(package), diag::OperandCountMismatch));
    CHECK_FALSE(foldConstants(package, fn));
    CHECK_EQ(package.inst(add).opcode, Opcode::Add);
}

TEST_CASE("verifier rejects an invalid operand ID") {
    Package package;
    auto builder = package.builder();
    auto fn = builder.createFunction("bad", builder.int64Type());
    auto block = builder.createBlock(package.function(fn).root_region);
    auto c = builder.addConstant(block, 1);
    auto bogus = InstId{999};
    auto add = builder.addInstForTesting(block, Opcode::Add, {c, bogus}, builder.int64Type());
    builder.addReturn(block, add);

    auto diags = verify(package);
    CHECK(hasDiagnostic(diags, diag::InvalidOperandId));
}

TEST_CASE("verifier rejects an operand type mismatch") {
    Package package;
    auto builder = package.builder();
    auto fn = builder.createFunction("bad", builder.int64Type());
    auto block = builder.createBlock(package.function(fn).root_region);
    auto c = builder.addConstant(block, 1);
    auto bad_void =
        builder.addInstForTesting(block, Opcode::Constant, {}, builder.voidType(), InstPayload(Int64Literal{0}));
    auto add = builder.addAdd(block, c, bad_void);
    builder.addReturn(block, add);

    auto diags = verify(package);
    CHECK(hasDiagnostic(diags, diag::OperandTypeMismatch));
}

TEST_CASE("verifier rejects a return value that doesn't match the function's result type") {
    Package package;
    auto builder = package.builder();
    auto fn = builder.createFunction("bad", builder.int64Type());
    auto block = builder.createBlock(package.function(fn).root_region);
    auto c = builder.addInstForTesting(block, Opcode::Constant, {}, builder.voidType(), InstPayload(Int64Literal{0}));
    builder.addReturn(block, c);

    auto diags = verify(package);
    CHECK(hasDiagnostic(diags, diag::ReturnTypeMismatch));
}

TEST_CASE("verifier rejects an unattached region and differentiates it from an empty package") {
    auto empty = makeSample();
    CHECK(verify(empty.package).empty());

    auto sample = makeSample();
    sample.package.builder().createRegion();
    auto diags = verify(sample.package);
    CHECK(hasDiagnostic(diags, diag::OrphanRegions));

    CHECK_NE(print(sample.package), print(empty.package));
}

TEST_CASE("verifier rejects a parser function whose region has more than one block") {
    Package package;
    auto builder = package.builder();
    auto unit = builder.createUnitDecl("Unit");
    auto fn = builder.createParserFunction(unit, builder.parserStateType(), builder.unitType(unit));
    auto region = package.function(fn).root_region;
    builder.createBlock(region);
    builder.createBlock(region);

    auto diags = verify(package);
    CHECK(hasDiagnostic(diags, diag::RegionBlockCountMismatch));
}

TEST_CASE("verifier rejects an ordinary function whose region has no block") {
    Package package;
    auto builder = package.builder();
    builder.createFunction("bad", builder.int64Type());

    auto diags = verify(package);
    CHECK(hasDiagnostic(diags, diag::RegionBlockCountMismatch));
}

TEST_CASE("verifier rejects an unrecognized opcode") {
    Package package;
    auto builder = package.builder();
    auto fn = builder.createFunction("bad", builder.int64Type());
    auto block = builder.createBlock(package.function(fn).root_region);
    auto bogus_op = static_cast<Opcode>(99);
    auto c = builder.addInstForTesting(block, bogus_op, {}, builder.int64Type());
    builder.addReturn(block, c);

    auto diags = verify(package);
    CHECK(hasDiagnostic(diags, diag::UnrecognizedOpcode));
}

TEST_CASE("verifier rejects an instruction after the block terminator") {
    Package package;
    auto builder = package.builder();
    auto fn = builder.createFunction("bad", builder.int64Type());
    auto block = builder.createBlock(package.function(fn).root_region);
    auto c = builder.addConstant(block, 1);
    builder.addReturn(block, c);
    builder.addConstant(block, 2);

    auto diags = verify(package);
    CHECK(hasDiagnostic(diags, diag::TerminatorNotLast));
}

TEST_CASE("parser repetition requires a byte-bounded state") {
    Package package;
    auto builder = package.builder();
    auto unit = builder.createUnitDecl("Root");
    auto field = builder.createFieldDecl(unit, "items", builder.vectorType(builder.uint8Type()));
    auto fn = builder.createParserFunction(unit, builder.parserStateType(), builder.unitType(unit));
    auto block = builder.createBlock(package.function(fn).root_region);
    auto state = builder.addArgument(fn, block, 0);
    auto root = builder.addUnitCreate(block, unit);
    auto vector = builder.addVectorEmpty(block, builder.uint8Type());
    auto body = builder.createRegion();
    auto body_block = builder.createBlock(body);
    auto body_state = builder.addRegionArgument(body_block, 0, builder.parserStateType());
    auto body_vector = builder.addRegionArgument(body_block, 1, package.inst(vector).result_type);
    auto yield = builder.addYield(body_block, {body_state, body_vector});
    auto repeated = builder.addRepeatToBound(block, {state, vector}, body);
    auto next_state = builder.addTupleGet(block, repeated, 0);
    auto items = builder.addTupleGet(block, repeated, 1);
    auto completed = builder.addPublishField(block, root, items, field);
    builder.addParserFinish(block, next_state, completed);
    builder.addParserRoot(unit, fn);

    CHECK(hasDiagnostic(verify(package), diag::RepeatRequiresBound));

    package.replaceInst(yield, Opcode::Yield, {body_state, body_state});
    CHECK(hasDiagnostic(verify(package), diag::InvalidYield));
}

TEST_CASE("parser repetition rejects a body that yields a state after leaving its bound") {
    Package package;
    auto builder = package.builder();
    auto unit = builder.createUnitDecl("Root");
    auto field = builder.createFieldDecl(unit, "items", builder.vectorType(builder.uint8Type()));
    auto fn = builder.createParserFunction(unit, builder.parserStateType(), builder.unitType(unit));
    auto block = builder.createBlock(package.function(fn).root_region);
    auto state = builder.addArgument(fn, block, 0);
    auto root = builder.addUnitCreate(block, unit);
    auto length = builder.addReadInteger(block,
                                         state,
                                         ReadIntegerPayload{
                                             .width = 64,
                                             .signedness = Signedness::Unsigned,
                                             .byte_order = ByteOrder::Network,
                                         });
    auto bounded =
        builder.addEnterBound(block, builder.addTupleGet(block, length, 0), builder.addTupleGet(block, length, 1));
    auto vector = builder.addVectorEmpty(block, builder.uint8Type());
    auto body = builder.createRegion();
    auto body_block = builder.createBlock(body);
    auto body_state = builder.addRegionArgument(body_block, 0, builder.parserStateType());
    auto body_vector = builder.addRegionArgument(body_block, 1, package.inst(vector).result_type);
    auto item = builder.addReadInteger(body_block,
                                       body_state,
                                       ReadIntegerPayload{
                                           .width = 8,
                                           .signedness = Signedness::Unsigned,
                                           .byte_order = ByteOrder::Network,
                                       });
    auto unbounded = builder.addLeaveBound(body_block, builder.addTupleGet(body_block, item, 0));
    builder.addYield(body_block, {unbounded, body_vector});
    auto repeated = builder.addRepeatToBound(block, {bounded, vector}, body);
    auto next_state = builder.addTupleGet(block, repeated, 0);
    auto items = builder.addTupleGet(block, repeated, 1);
    auto completed = builder.addPublishField(block, root, items, field);
    builder.addParserFinish(block, next_state, completed);
    builder.addParserRoot(unit, fn);

    CHECK(hasDiagnostic(verify(package), diag::InvalidYield));
}

TEST_CASE("parser repetition rejects region arguments beyond its carried values") {
    Package package;
    auto builder = package.builder();
    auto unit = builder.createUnitDecl("Root");
    auto field = builder.createFieldDecl(unit, "items", builder.vectorType(builder.uint8Type()));
    auto fn = builder.createParserFunction(unit, builder.parserStateType(), builder.unitType(unit));
    auto block = builder.createBlock(package.function(fn).root_region);
    auto state = builder.addArgument(fn, block, 0);
    auto root = builder.addUnitCreate(block, unit);
    auto vector = builder.addVectorEmpty(block, builder.uint8Type());
    auto body = builder.createRegion();
    auto body_block = builder.createBlock(body);
    auto body_state = builder.addRegionArgument(body_block, 0, builder.parserStateType());
    auto body_vector = builder.addRegionArgument(body_block, 1, package.inst(vector).result_type);
    builder.addRegionArgument(body_block, 123, builder.parserStateType());
    builder.addYield(body_block, {body_state, body_vector});
    auto repeated = builder.addRepeatToBound(block, {state, vector}, body);
    auto next_state = builder.addTupleGet(block, repeated, 0);
    auto items = builder.addTupleGet(block, repeated, 1);
    auto completed = builder.addPublishField(block, root, items, field);
    builder.addParserFinish(block, next_state, completed);
    builder.addParserRoot(unit, fn);

    CHECK(hasDiagnostic(verify(package), diag::InvalidRegionArgument));
}

TEST_CASE("uint8 and parser.state intern deterministically and are stable across repeated requests") {
    Package package;
    auto builder = package.builder();
    auto uint8_1 = builder.uint8Type();
    auto uint8_2 = builder.uint8Type();
    CHECK_EQ(uint8_1, uint8_2);
    CHECK_EQ(package.type(uint8_1).kind, TypeKind::UInt8);

    auto state_1 = builder.parserStateType();
    auto state_2 = builder.parserStateType();
    CHECK_EQ(state_1, state_2);
    CHECK_EQ(package.type(state_1).kind, TypeKind::ParserState);

    CHECK_NE(uint8_1, state_1);
}

TEST_CASE("unit and tuple types intern structurally and repeated requests return the same TypeId") {
    Package package;
    auto builder = package.builder();
    auto unit_decl = builder.createUnitDecl("OneByte");

    auto unit_1 = builder.unitType(unit_decl);
    auto unit_2 = builder.unitType(unit_decl);
    CHECK_EQ(unit_1, unit_2);
    CHECK_EQ(package.type(unit_1).kind, TypeKind::Unit);
    CHECK_EQ(package.type(unit_1).declaration, unit_decl);

    auto uint8 = builder.uint8Type();
    auto state = builder.parserStateType();
    auto tuple_1 = builder.tupleType({state, uint8});
    auto tuple_2 = builder.tupleType({state, uint8});
    CHECK_EQ(tuple_1, tuple_2);
    CHECK_EQ(package.type(tuple_1).kind, TypeKind::Tuple);
    CHECK_EQ(package.type(tuple_1).type_arguments, std::vector<TypeId>{state, uint8});

    // Different element order is a different structural type.
    auto tuple_3 = builder.tupleType({uint8, state});
    CHECK_NE(tuple_1, tuple_3);
}

TEST_CASE("two unit declarations with the same name remain distinct nominal types") {
    Package package;
    auto builder = package.builder();
    auto decl_a = builder.createUnitDecl("Same");
    auto decl_b = builder.createUnitDecl("Same");
    CHECK_NE(decl_a, decl_b);

    auto type_a = builder.unitType(decl_a);
    auto type_b = builder.unitType(decl_b);
    CHECK_NE(type_a, type_b);
}

TEST_CASE("procedural-only packages retain canonical type numbering") {
    auto sample = makeSample();
    auto builder = sample.package.builder();
    CHECK_EQ(sample.package.types().size(), 2);
    CHECK_EQ(builder.voidType(), TypeId{0});
    CHECK_EQ(builder.int64Type(), TypeId{1});
}

TEST_CASE("field declarations are appended to their owning unit in call order") {
    Package package;
    auto builder = package.builder();
    auto unit_decl = builder.createUnitDecl("OneByte");
    auto uint8 = builder.uint8Type();
    auto field_a = builder.createFieldDecl(unit_decl, "a", uint8);
    auto field_b = builder.createFieldDecl(unit_decl, "b", uint8);

    CHECK_EQ(package.typeDecl(unit_decl).fields, std::vector<DeclId>{field_a, field_b});
    CHECK_EQ(package.declaration(field_a).owner, unit_decl);
    CHECK_EQ(package.declaration(field_b).owner, unit_decl);
}

TEST_CASE("verifier rejects an invalid type declaration on a unit type without asserting") {
    Package package;
    // Deliberately malformed: no declared unit backs this type ID's declaration.
    auto unit_decl_placeholder = TypeDeclId{999};
    package.builder().unitType(unit_decl_placeholder);

    auto diags = verify(package);
    CHECK(hasDiagnostic(diags, diag::TypeMissingDeclaration));
}

TEST_CASE("verifier rejects an invalid tuple element type without asserting") {
    Package package;
    package.builder().tupleType({TypeId{999}});

    auto diags = verify(package);
    CHECK(hasDiagnostic(diags, diag::TypeInvalidTypeArgument));
}

TEST_CASE("verifier rejects a field with an invalid owner or type without asserting") {
    Package package;
    auto builder = package.builder();
    auto unit_decl = builder.createUnitDecl("OneByte");
    builder.createFieldDecl(unit_decl, "value", TypeId{999});

    auto diags = verify(package);
    CHECK(hasDiagnostic(diags, diag::InvalidFieldType));
}

TEST_SUITE_END();

namespace {

OpaqueTypeInfo completeOpaqueInfo(std::string cxx_name) {
    return OpaqueTypeInfo{.cxx_name = std::move(cxx_name), .lifecycle = OpaqueLifecycle{.copyable = true}};
}

} // namespace

TEST_CASE("opaque types intern by declaration and never by rendered name") {
    Package package;
    auto builder = package.builder();
    auto decl_a = builder.createOpaqueTypeDecl("Same", completeOpaqueInfo("::Same"));
    auto decl_b = builder.createOpaqueTypeDecl("Same", completeOpaqueInfo("::Same"));

    auto type_a = builder.opaqueType(decl_a);
    auto type_b = builder.opaqueType(decl_b);
    CHECK_NE(type_a, type_b);
    CHECK_EQ(builder.opaqueType(decl_a), type_a);
}

TEST_CASE("a resolved foreign call verifies and prints with its native binding") {
    Package package;
    auto builder = package.builder();
    auto handle = builder.opaqueType(builder.createOpaqueTypeDecl("Handle", completeOpaqueInfo("::Handle")));
    auto make = builder.createForeignFunction("make", "::make_handle", {builder.int64Type()}, handle);

    auto fn = builder.createFunction("caller", handle);
    auto block = builder.createBlock(package.function(fn).root_region);
    auto arg = builder.addConstant(block, 7);
    auto made = builder.addOpaqueOp(block, make, {arg});
    builder.addReturn(block, made);

    CHECK(verify(package).empty());
    auto dump = print(package);
    CHECK(dump.find("opaque.op") != std::string::npos);
    CHECK(dump.find("foreign function %0 \"make\" (native \"::make_handle\")") != std::string::npos);
}

TEST_CASE("a foreign call without arguments verifies") {
    Package package;
    auto builder = package.builder();
    auto now = builder.createForeignFunction("now", "::now", {}, builder.int64Type());

    auto fn = builder.createFunction("caller", builder.int64Type());
    auto block = builder.createBlock(package.function(fn).root_region);
    auto value = builder.addOpaqueOp(block, now, {});
    builder.addReturn(block, value);

    CHECK(verify(package).empty());
}

TEST_CASE("foreign calls are conservative for every analysis") {
    const auto effects = effectsFor(Opcode::OpaqueOp);
    CHECK(effects.reads_world);
    CHECK(effects.writes_world);
    CHECK(effects.may_fail);
    CHECK_FALSE(schemaFor(Opcode::OpaqueOp)->is_pure);
}

TEST_CASE("verifier rejects an opaque argument of a distinct opaque type") {
    Package package;
    auto builder = package.builder();
    auto handle_a = builder.opaqueType(builder.createOpaqueTypeDecl("A", completeOpaqueInfo("::A")));
    auto handle_b = builder.opaqueType(builder.createOpaqueTypeDecl("B", completeOpaqueInfo("::B")));
    auto make_b = builder.createForeignFunction("make_b", "::make_b", {}, handle_b);
    auto consume = builder.createForeignFunction("consume", "::consume", {handle_a}, builder.int64Type());

    auto fn = builder.createFunction("caller", builder.int64Type());
    auto block = builder.createBlock(package.function(fn).root_region);
    auto value = builder.addOpaqueOp(block, make_b, {});
    auto result = builder.addOpaqueOp(block, consume, {value});
    builder.addReturn(block, result);

    CHECK(hasDiagnostic(verify(package), diag::OpaqueOpArgumentTypeMismatch));
}

TEST_CASE("verifier rejects a foreign call with the wrong argument count") {
    Package package;
    auto builder = package.builder();
    auto consume = builder.createForeignFunction("consume", "::consume", {builder.int64Type()}, builder.int64Type());

    auto fn = builder.createFunction("caller", builder.int64Type());
    auto block = builder.createBlock(package.function(fn).root_region);
    auto result = builder.addOpaqueOp(block, consume, {});
    builder.addReturn(block, result);

    CHECK(hasDiagnostic(verify(package), diag::OpaqueOpArgumentCountMismatch));
}

TEST_CASE("verifier rejects a foreign call whose result type differs from its declaration") {
    Package package;
    auto builder = package.builder();
    auto handle = builder.opaqueType(builder.createOpaqueTypeDecl("Handle", completeOpaqueInfo("::Handle")));
    auto make = builder.createForeignFunction("make", "::make_handle", {}, handle);

    auto fn = builder.createFunction("caller", builder.int64Type());
    auto block = builder.createBlock(package.function(fn).root_region);
    auto call = builder.addInstForTesting(block,
                                          Opcode::OpaqueOp,
                                          {},
                                          builder.int64Type(),
                                          InstPayload(ForeignFunctionPayload{make}));
    builder.addReturn(block, call);

    CHECK(hasDiagnostic(verify(package), diag::OpaqueOpResultTypeMismatch));
}

TEST_CASE("verifier rejects an opaque op that references no foreign function") {
    Package package;
    auto builder = package.builder();

    auto fn = builder.createFunction("caller", builder.int64Type());
    auto block = builder.createBlock(package.function(fn).root_region);
    auto call = builder.addInstForTesting(block,
                                          Opcode::OpaqueOp,
                                          {},
                                          builder.int64Type(),
                                          InstPayload(ForeignFunctionPayload{ForeignFunctionId{999}}));
    builder.addReturn(block, call);

    CHECK(hasDiagnostic(verify(package), diag::OpaqueOpInvalidPayload));
}

TEST_CASE("verifier rejects an opaque declaration without a native name or lifecycle") {
    Package package;
    auto builder = package.builder();
    builder.createOpaqueTypeDecl("Unnamed", OpaqueTypeInfo{.lifecycle = OpaqueLifecycle{}});
    builder.createOpaqueTypeDecl("Undeclared", OpaqueTypeInfo{.cxx_name = "::Undeclared"});

    CHECK(hasDiagnostic(verify(package), diag::OpaqueDeclarationIncomplete));
}

TEST_CASE("verifier rejects a foreign function without a binding or with an affine parameter") {
    Package package;
    auto builder = package.builder();
    auto unit = builder.unitType(builder.createUnitDecl("Unit"));
    builder.createForeignFunction("unbound", "", {builder.int64Type()}, builder.int64Type());
    builder.createForeignFunction("affine", "::affine", {unit}, builder.int64Type());

    auto diags = verify(package);
    CHECK(hasDiagnostic(diags, diag::ForeignFunctionMissingBinding));
    CHECK(hasDiagnostic(diags, diag::ForeignFunctionInvalidParameter));
}

TEST_CASE("places intern structurally by element type") {
    Package package;
    auto builder = package.builder();
    auto place = builder.placeType(builder.int64Type());

    CHECK_EQ(builder.placeType(builder.int64Type()), place);
    CHECK_NE(builder.placeType(builder.uint8Type()), place);
}

TEST_CASE("a call with a local place verifies and prints") {
    Package package;
    auto builder = package.builder();

    auto increment = builder.createFunction("increment", {builder.int64Type()}, builder.int64Type());
    auto increment_block = builder.createBlock(package.function(increment).root_region);
    auto x = builder.addArgument(increment, increment_block, 0);
    auto one = builder.addConstant(increment_block, 1);
    builder.addReturn(increment_block, builder.addAdd(increment_block, x, one));

    auto fn = builder.createFunction("caller", builder.int64Type());
    auto block = builder.createBlock(package.function(fn).root_region);
    auto place = builder.addLocalPlace(block, builder.addConstant(block, 5));
    auto value = builder.addLoad(block, place);
    auto result = builder.addCall(block, increment, {value});
    builder.addStore(block, place, result);
    builder.addReturn(block, builder.addLoad(block, place));

    CHECK(verify(package).empty());
    auto dump = print(package);
    CHECK(dump.find("core.local_place") != std::string::npos);
    CHECK(dump.find("core.call") != std::string::npos);
    CHECK(dump.find("core.store") != std::string::npos);
    CHECK(dump.find("place<int64>") != std::string::npos);
}

TEST_CASE("verifier rejects a store whose value differs from the place's element type") {
    Package package;
    auto builder = package.builder();
    auto fn = builder.createFunction("bad", builder.int64Type());
    auto block = builder.createBlock(package.function(fn).root_region);
    auto place = builder.addLocalPlace(block, builder.addConstant(block, 1));
    auto byte =
        builder.addInstForTesting(block, Opcode::Constant, {}, builder.uint8Type(), InstPayload(Int64Literal{2}));
    builder.addStore(block, place, byte);
    builder.addReturn(block, builder.addLoad(block, place));

    CHECK(hasDiagnostic(verify(package), diag::StoreValueTypeMismatch));
}

TEST_CASE("verifier rejects a load and a store whose operand is not a place") {
    Package package;
    auto builder = package.builder();
    auto fn = builder.createFunction("bad", builder.int64Type());
    auto block = builder.createBlock(package.function(fn).root_region);
    auto not_a_place = builder.addConstant(block, 1);
    auto loaded = builder.addLoad(block, not_a_place);
    builder.addStore(block, not_a_place, loaded);
    builder.addReturn(block, loaded);

    CHECK(hasDiagnostic(verify(package), diag::PlaceOperandMismatch));
}

TEST_CASE("verifier rejects a call to a parser function") {
    Package package;
    auto builder = package.builder();
    auto unit = builder.createUnitDecl("Unit");
    auto parser = builder.createParserFunction(unit, builder.parserStateType(), builder.unitType(unit));

    auto fn = builder.createFunction("caller", builder.int64Type());
    auto block = builder.createBlock(package.function(fn).root_region);
    builder.addReturn(block, builder.addCall(block, parser, {}));

    CHECK(hasDiagnostic(verify(package), diag::CallTargetNotNormal));
}

TEST_CASE("verifier rejects a call with the wrong argument count") {
    Package package;
    auto builder = package.builder();
    auto callee = builder.createFunction("callee", {builder.int64Type()}, builder.int64Type());
    auto callee_block = builder.createBlock(package.function(callee).root_region);
    builder.addReturn(callee_block, builder.addArgument(callee, callee_block, 0));

    auto fn = builder.createFunction("caller", builder.int64Type());
    auto block = builder.createBlock(package.function(fn).root_region);
    builder.addReturn(block, builder.addCall(block, callee, {}));

    CHECK(hasDiagnostic(verify(package), diag::CallArgumentCountMismatch));
}

TEST_CASE("verifier rejects a place stored in a tuple or returned from a function") {
    Package package;
    auto builder = package.builder();
    auto place = builder.placeType(builder.int64Type());
    builder.tupleType({place});

    auto fn = builder.createFunction("returns_place", place);
    auto block = builder.createBlock(package.function(fn).root_region);
    builder.addInstForTesting(block, Opcode::Constant, {}, place, InstPayload(Int64Literal{0}));
    builder.addInstForTesting(block, Opcode::Return, {}, place);

    auto diags = verify(package);
    CHECK(hasDiagnostic(diags, diag::PlaceEscapes));
}

TEST_CASE("verifier rejects a local place initialized with a void value") {
    Package package;
    auto builder = package.builder();
    auto fn = builder.createFunction("bad", builder.int64Type());
    auto block = builder.createBlock(package.function(fn).root_region);
    auto void_value =
        builder.addInstForTesting(block, Opcode::Constant, {}, builder.voidType(), InstPayload(Int64Literal{0}));
    builder.addLocalPlace(block, void_value);
    builder.addReturn(block, builder.addConstant(block, 0));

    CHECK(hasDiagnostic(verify(package), diag::LocalPlaceInvalidInitial));
}

TEST_CASE("verifier rejects a function root that is not an ordinary function") {
    Package package;
    auto builder = package.builder();
    auto unit = builder.createUnitDecl("Unit");
    builder.addFunctionRoot(builder.createParserFunction(unit, builder.parserStateType(), builder.unitType(unit)));

    CHECK(hasDiagnostic(verify(package), diag::FunctionRootNotNormal));
}

TEST_CASE("verifier rejects a function root that references no function") {
    Package package;
    package.builder().addFunctionRoot(FunctionId{999});

    CHECK(hasDiagnostic(verify(package), diag::InvalidFunctionRoot));
}

TEST_CASE("bool, string, bytes, and tuple values verify and print") {
    Package package;
    auto builder = package.builder();
    auto fn = builder.createFunction("values", builder.voidType());
    auto block = builder.createBlock(package.function(fn).root_region);
    auto flag = builder.addBoolConstant(block, true);
    auto text = builder.addStringConstant(block, "text");
    auto data = builder.addBytesConstant(block, "data");
    builder.addTuple(block, {flag, text, data});
    builder.addReturnVoid(block);

    CHECK(verify(package).empty());
    auto dump = print(package);
    CHECK(dump.find("core.bool_constant") != std::string::npos);
    CHECK(dump.find("core.string_constant \"text\"") != std::string::npos);
    CHECK(dump.find("core.bytes_constant b\"data\"") != std::string::npos);
    CHECK(dump.find("tuple<bool, string, bytes>") != std::string::npos);
}

TEST_CASE("verifier rejects a tuple whose result does not match its operands") {
    Package package;
    auto builder = package.builder();
    auto fn = builder.createFunction("bad", builder.voidType());
    auto block = builder.createBlock(package.function(fn).root_region);
    auto value = builder.addConstant(block, 1);
    builder.addInstForTesting(block, Opcode::Tuple, {value}, builder.tupleType({builder.uint8Type()}));
    builder.addReturnVoid(block);

    CHECK(hasDiagnostic(verify(package), diag::TupleResultTypeMismatch));
}

namespace {

ForeignParameter anyParameter() { return ForeignParameter{TypeId(), ForeignArgument::TypeInfo}; }
ForeignParameter tupleParameter() { return ForeignParameter{TypeId(), ForeignArgument::AnyTuple}; }

} // namespace

TEST_CASE("a native any formal accepts any copyable operand, and a tuple formal accepts only tuples") {
    Package package;
    auto builder = package.builder();
    auto show = builder.createForeignFunction("show", "::show", {anyParameter()}, builder.voidType());
    auto show_tuple =
        builder.createForeignFunction("show_tuple", "::show_tuple", {tupleParameter()}, builder.voidType());
    auto show_pointer = builder.createForeignFunction("show_pointer",
                                                      "::show_pointer",
                                                      {ForeignParameter{TypeId(), ForeignArgument::AnyPointer}},
                                                      builder.voidType());

    auto fn = builder.createFunction("caller", builder.voidType());
    auto block = builder.createBlock(package.function(fn).root_region);
    builder.addOpaqueOp(block, show, {builder.addConstant(block, 1)});
    builder.addOpaqueOp(block, show, {builder.addBoolConstant(block, false)});
    builder.addOpaqueOp(block, show_pointer, {builder.addConstant(block, 3)});
    builder.addOpaqueOp(block, show_tuple, {builder.addTuple(block, {builder.addConstant(block, 2)})});
    builder.addReturnVoid(block);
    CHECK(verify(package).empty());

    Package bad;
    auto bad_builder = bad.builder();
    auto tuple_only = bad_builder.createForeignFunction("show_tuple",
                                                        "::show_tuple",
                                                        {ForeignParameter{TypeId(), ForeignArgument::AnyTuple}},
                                                        bad_builder.voidType());
    auto bad_fn = bad_builder.createFunction("caller", bad_builder.voidType());
    auto bad_block = bad_builder.createBlock(bad.function(bad_fn).root_region);
    bad_builder.addOpaqueOp(bad_block, tuple_only, {bad_builder.addConstant(bad_block, 1)});
    bad_builder.addReturnVoid(bad_block);

    CHECK(hasDiagnostic(verify(bad), diag::OpaqueOpArgumentTypeMismatch));
}

TEST_CASE("verifier rejects a load that copies an opaque value not declared copyable") {
    Package package;
    auto builder = package.builder();
    OpaqueTypeInfo info;
    info.cxx_name = "::Handle";
    info.lifecycle = OpaqueLifecycle{.copyable = false, .movable = true};
    auto handle = builder.opaqueType(builder.createOpaqueTypeDecl("Handle", info));
    auto make = builder.createForeignFunction("make", "::make", {}, handle);

    auto fn = builder.createFunction("caller", builder.voidType());
    auto block = builder.createBlock(package.function(fn).root_region);
    auto place = builder.addLocalPlace(block, builder.addOpaqueOp(block, make, {}));
    builder.addLoad(block, place);
    builder.addReturnVoid(block);

    CHECK(hasDiagnostic(verify(package), diag::OpaqueLoadRequiresCopyable));
}

TEST_CASE("verifier checks call operands even though calls declare no operand types") {
    Package package;
    auto builder = package.builder();
    auto callee = builder.createFunction("callee", {builder.int64Type()}, builder.int64Type());
    auto callee_block = builder.createBlock(package.function(callee).root_region);
    auto callee_arg = builder.addArgument(callee, callee_block, 0);
    builder.addReturn(callee_block, callee_arg);

    auto invalid = builder.createFunction("invalid", builder.int64Type());
    auto invalid_block = builder.createBlock(package.function(invalid).root_region);
    builder.addReturn(invalid_block, builder.addCall(invalid_block, callee, {InstId{9999}}));
    CHECK(hasDiagnostic(verify(package), diag::InvalidOperandId));

    auto foreign = builder.createFunction("foreign", builder.int64Type());
    auto foreign_block = builder.createBlock(package.function(foreign).root_region);
    builder.addReturn(foreign_block, builder.addCall(foreign_block, callee, {callee_arg}));
    CHECK(hasDiagnostic(verify(package), diag::OperandNotSameBlock));

    Package cyclic;
    auto cyclic_builder = cyclic.builder();
    auto cyclic_callee =
        cyclic_builder.createFunction("callee", {cyclic_builder.int64Type()}, cyclic_builder.int64Type());
    auto cyclic_callee_block = cyclic_builder.createBlock(cyclic.function(cyclic_callee).root_region);
    cyclic_builder.addReturn(cyclic_callee_block, cyclic_builder.addArgument(cyclic_callee, cyclic_callee_block, 0));

    auto fn = cyclic_builder.createFunction("caller", cyclic_builder.int64Type());
    auto block = cyclic_builder.createBlock(cyclic.function(fn).root_region);
    auto constant = cyclic_builder.addConstant(block, 42);
    auto call = cyclic_builder.addCall(block, cyclic_callee, {constant});
    cyclic.replaceInst(constant, Opcode::Call, {call}, FunctionPayload{cyclic_callee});
    cyclic_builder.addReturn(block, call);
    CHECK(hasDiagnostic(verify(cyclic), diag::OperandUsedBeforeDefinition));
}

TEST_CASE("a field place addresses a field of the unit that declares it") {
    Package package;
    auto builder = package.builder();
    auto unit = builder.createUnitDecl("Unit");
    auto field = builder.createFieldDecl(unit, "length", builder.uint64Type());

    auto fn = builder.createFunction("caller", builder.voidType());
    auto block = builder.createBlock(package.function(fn).root_region);
    auto unit_value = builder.addUnitCreate(block, unit);
    builder.addLoad(block, builder.addFieldPlace(block, unit_value, field));
    builder.addReturnVoid(block);

    CHECK(verify(package).empty());
    CHECK(print(package).find("unit.field_place") != std::string::npos);
}

TEST_CASE("verifier rejects a field place on a unit that does not declare the field") {
    Package package;
    auto builder = package.builder();
    auto owner = builder.createUnitDecl("Owner");
    auto other = builder.createUnitDecl("Other");
    auto field = builder.createFieldDecl(owner, "length", builder.uint64Type());

    auto fn = builder.createFunction("caller", builder.voidType());
    auto block = builder.createBlock(package.function(fn).root_region);
    auto unit_value = builder.addUnitCreate(block, other);
    builder.addFieldPlace(block, unit_value, field);
    builder.addReturnVoid(block);

    CHECK(hasDiagnostic(verify(package), diag::FieldPlaceUnitMismatch));
}

TEST_CASE("verifier rejects a field place with an invalid field or a result that is not a place of the field") {
    Package package;
    auto builder = package.builder();
    auto unit = builder.createUnitDecl("Unit");
    auto field = builder.createFieldDecl(unit, "length", builder.uint64Type());

    auto fn = builder.createFunction("caller", builder.voidType());
    auto block = builder.createBlock(package.function(fn).root_region);
    auto unit_value = builder.addUnitCreate(block, unit);
    builder.addInstForTesting(block,
                              Opcode::FieldPlace,
                              {unit_value},
                              builder.placeType(builder.uint8Type()),
                              InstPayload(FieldPayload{field}));
    builder.addInstForTesting(block,
                              Opcode::FieldPlace,
                              {unit_value},
                              builder.voidType(),
                              InstPayload(FieldPayload{DeclId{999}}));
    builder.addReturnVoid(block);

    auto diags = verify(package);
    CHECK(hasDiagnostic(diags, diag::FieldPlaceResultTypeMismatch));
    CHECK(hasDiagnostic(diags, diag::FieldPlaceInvalidPayload));
}

TEST_CASE("an ordinary function may branch, and a value defined before the branch is used after the join") {
    Package package;
    auto builder = package.builder();
    auto fn = builder.createFunction("pick", {builder.boolType()}, builder.int64Type());
    auto region = package.function(fn).root_region;
    auto entry = builder.createBlock(region);
    auto then_block = builder.createBlock(region);
    auto else_block = builder.createBlock(region);
    auto join = builder.createBlock(region);

    auto flag = builder.addArgument(fn, entry, 0);
    auto base = builder.addConstant(entry, 40);
    builder.addBranch(entry, flag, then_block, else_block);

    builder.addJump(then_block, join);
    builder.addJump(else_block, join);

    builder.addReturn(join, builder.addAdd(join, base, builder.addConstant(join, 2)));

    CHECK(verify(package).empty());
    auto dump = print(package);
    CHECK(dump.find("core.branch %0, then %1, else %2") != std::string::npos);
    CHECK(dump.find("core.jump %3") != std::string::npos);
}

TEST_CASE("an ordinary function whose arms both return leaves no join block") {
    Package package;
    auto builder = package.builder();
    auto fn = builder.createFunction("pick", {builder.boolType()}, builder.int64Type());
    auto region = package.function(fn).root_region;
    auto entry = builder.createBlock(region);
    auto then_block = builder.createBlock(region);
    auto else_block = builder.createBlock(region);

    auto flag = builder.addArgument(fn, entry, 0);
    builder.addBranch(entry, flag, then_block, else_block);
    builder.addReturn(then_block, builder.addConstant(then_block, 1));
    builder.addReturn(else_block, builder.addConstant(else_block, 2));

    CHECK(verify(package).empty());
}

TEST_CASE("verifier rejects a branch on a condition that is not a bool") {
    Package package;
    auto builder = package.builder();
    auto fn = builder.createFunction("bad", builder.int64Type());
    auto region = package.function(fn).root_region;
    auto entry = builder.createBlock(region);
    auto then_block = builder.createBlock(region);
    auto else_block = builder.createBlock(region);

    builder.addBranch(entry, builder.addConstant(entry, 1), then_block, else_block);
    builder.addReturn(then_block, builder.addConstant(then_block, 1));
    builder.addReturn(else_block, builder.addConstant(else_block, 2));

    CHECK(hasDiagnostic(verify(package), diag::OperandTypeMismatch));
}

TEST_CASE("verifier rejects a successor that belongs to another function body") {
    Package package;
    auto builder = package.builder();
    auto other = builder.createFunction("other", builder.int64Type());
    auto other_block = builder.createBlock(package.function(other).root_region);
    builder.addReturn(other_block, builder.addConstant(other_block, 1));

    auto fn = builder.createFunction("bad", builder.int64Type());
    auto entry = builder.createBlock(package.function(fn).root_region);
    builder.addJump(entry, other_block);

    CHECK(hasDiagnostic(verify(package), diag::InvalidSuccessor));
}

TEST_CASE("verifier rejects a cycle in an ordinary function's control flow") {
    Package package;
    auto builder = package.builder();
    auto fn = builder.createFunction("loop", builder.int64Type());
    auto region = package.function(fn).root_region;
    auto first = builder.createBlock(region);
    auto second = builder.createBlock(region);
    builder.addJump(first, second);
    builder.addJump(second, first);

    CHECK(hasDiagnostic(verify(package), diag::ControlFlowCycle));
}

TEST_CASE("verifier rejects a value used in a block that its defining block does not dominate") {
    Package package;
    auto builder = package.builder();
    auto fn = builder.createFunction("bad", builder.int64Type());
    auto region = package.function(fn).root_region;
    auto entry = builder.createBlock(region);
    auto then_block = builder.createBlock(region);
    auto else_block = builder.createBlock(region);
    auto join = builder.createBlock(region);

    builder.addBranch(entry, builder.addBoolConstant(entry, true), then_block, else_block);
    auto only_on_then = builder.addConstant(then_block, 1);
    builder.addJump(then_block, join);
    builder.addJump(else_block, join);
    builder.addReturn(join, only_on_then);

    CHECK(hasDiagnostic(verify(package), diag::OperandNotSameBlock));
}

TEST_CASE("core.equal compares two integers or two bools of one type and yields a bool") {
    Package package;
    auto builder = package.builder();
    auto fn = builder.createFunction("compare", builder.int64Type());
    auto block = builder.createBlock(package.function(fn).root_region);
    builder.addEqual(block, builder.addConstant(block, 1), builder.addConstant(block, 2));
    builder.addEqual(block, builder.addBoolConstant(block, true), builder.addBoolConstant(block, false));
    builder.addReturn(block, builder.addConstant(block, 0));

    CHECK(verify(package).empty());
    CHECK(print(package).find("core.equal") != std::string::npos);
}

TEST_CASE("verifier rejects core.equal on operands of different or non-comparable types") {
    Package package;
    auto builder = package.builder();
    auto fn = builder.createFunction("bad", builder.int64Type());
    auto block = builder.createBlock(package.function(fn).root_region);
    builder.addEqual(block, builder.addConstant(block, 1), builder.addBoolConstant(block, true));
    builder.addEqual(block, builder.addBytesConstant(block, "a"), builder.addBytesConstant(block, "a"));
    builder.addReturn(block, builder.addConstant(block, 0));

    CHECK(hasDiagnostic(verify(package), diag::EqualOperandTypeMismatch));
}

TEST_CASE("verifier rejects a branch or jump in a parser function") {
    Package package;
    auto builder = package.builder();
    auto unit = builder.createUnitDecl("Unit");
    auto fn = builder.createParserFunction(unit, builder.parserStateType(), builder.unitType(unit));
    auto region = package.function(fn).root_region;
    auto first = builder.createBlock(region);
    builder.addJump(first, first);

    CHECK(hasDiagnostic(verify(package), diag::ControlFlowOutsideFunctionBody));
}

TEST_CASE("an affine value consumed on each of two exclusive arms is consumed once per path") {
    Package package;
    auto builder = package.builder();
    auto fn = builder.createFunction("fill", {builder.boolType()}, builder.voidType());
    auto region = package.function(fn).root_region;
    auto entry = builder.createBlock(region);
    auto then_block = builder.createBlock(region);
    auto else_block = builder.createBlock(region);

    auto flag = builder.addArgument(fn, entry, 0);
    auto vector = builder.addVectorEmpty(entry, builder.int64Type());
    builder.addBranch(entry, flag, then_block, else_block);
    builder.addVectorAppend(then_block, vector, builder.addConstant(then_block, 1));
    builder.addReturnVoid(then_block);
    builder.addVectorAppend(else_block, vector, builder.addConstant(else_block, 2));
    builder.addReturnVoid(else_block);

    CHECK(verify(package).empty());
}

TEST_CASE("verifier rejects an affine value consumed on a path that reaches a second consumer") {
    Package package;
    auto builder = package.builder();
    auto fn = builder.createFunction("fill", {builder.boolType()}, builder.voidType());
    auto region = package.function(fn).root_region;
    auto entry = builder.createBlock(region);
    auto then_block = builder.createBlock(region);
    auto join = builder.createBlock(region);

    auto flag = builder.addArgument(fn, entry, 0);
    auto vector = builder.addVectorEmpty(entry, builder.int64Type());
    builder.addBranch(entry, flag, then_block, join);
    builder.addVectorAppend(then_block, vector, builder.addConstant(then_block, 1));
    builder.addJump(then_block, join);
    builder.addVectorAppend(join, vector, builder.addConstant(join, 2));
    builder.addReturnVoid(join);

    CHECK(hasDiagnostic(verify(package), diag::ParserStateReused));
}

TEST_CASE("the dominator tree and post-dominators of a diamond") {
    // 0 -> {1, 2}, 1 -> 3, 2 -> 3, and 3 exits.
    std::vector<std::vector<size_t>> successors = {{1, 2}, {3}, {3}, {}};
    auto idom = immediateDominators(successors, 0);
    CHECK(idom == std::vector<size_t>{0, 0, 0, 0});
    CHECK(dominates(idom, 0, 3));
    CHECK_FALSE(dominates(idom, 1, 3));

    Package package;
    auto builder = package.builder();
    auto fn = builder.createFunction("diamond", {builder.boolType()}, builder.int64Type());
    auto region = package.function(fn).root_region;
    auto entry = builder.createBlock(region);
    auto left = builder.createBlock(region);
    auto right = builder.createBlock(region);
    auto join = builder.createBlock(region);
    builder.addBranch(entry, builder.addArgument(fn, entry, 0), left, right);
    builder.addJump(left, join);
    builder.addJump(right, join);
    builder.addReturn(join, builder.addConstant(join, 0));

    auto cfg = buildCfg(package, region);
    CHECK(isAcyclic(cfg));
    auto ipdom = immediatePostDominators(cfg);
    CHECK(ipdom[0].kind == PostDominator::Kind::Block);
    CHECK(ipdom[0].position == 3);
    CHECK(ipdom[3].kind == PostDominator::Kind::Exit);
    CHECK(isStructured(cfg, branchJoins(cfg)));
}

TEST_CASE("postorder follows successors in order, tolerates cycles, and omits unreachable positions") {
    // 0 -> {1, 2}, 1 -> 0 (a cycle), 2 -> {}, and 3 is unreachable from 0.
    std::vector<std::vector<size_t>> successors = {{1, 2}, {0}, {}, {0}};
    CHECK(postorder(successors, 0) == std::vector<size_t>{1, 2, 0});
    CHECK(postorder({{1}, {0}}, 0) == std::vector<size_t>{1, 0});
}

TEST_CASE("an early return inside a nested guard still structures to one emission per block") {
    // if (a) { if (b) return 1; } return 2;  -- the inner return cuts across the outer join.
    Package package;
    auto builder = package.builder();
    auto fn = builder.createFunction("pick", {builder.boolType(), builder.boolType()}, builder.int64Type());
    auto region = package.function(fn).root_region;
    auto entry = builder.createBlock(region);
    auto outer_then = builder.createBlock(region);
    auto outer_else = builder.createBlock(region);
    auto inner_then = builder.createBlock(region);
    auto inner_else = builder.createBlock(region);
    auto inner_join = builder.createBlock(region);
    auto join = builder.createBlock(region);

    auto a = builder.addArgument(fn, entry, 0);
    auto b = builder.addArgument(fn, entry, 1);
    builder.addBranch(entry, a, outer_then, outer_else);
    builder.addBranch(outer_then, b, inner_then, inner_else);
    builder.addReturn(inner_then, builder.addConstant(inner_then, 1));
    builder.addJump(inner_else, inner_join);
    builder.addJump(inner_join, join);
    builder.addJump(outer_else, join);
    builder.addReturn(join, builder.addConstant(join, 2));

    CHECK(verify(package).empty());
    auto cfg = buildCfg(package, region);
    auto joins = branchJoins(cfg);
    CHECK(joins[0] == std::optional<size_t>(cfg.position.at(join.index)));
    CHECK(isStructured(cfg, joins));
}

TEST_CASE("two arms that both reach the same two returning blocks are not structured") {
    // 0 -> {1, 2}, 1 -> {3, 4}, 2 -> {3, 4}: each arm reaches both exits, so one of them is emitted twice.
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
    builder.addReturn(b3, builder.addConstant(b3, 1));
    builder.addReturn(b4, builder.addConstant(b4, 2));

    CHECK(verify(package).empty());
    auto cfg = buildCfg(package, region);
    CHECK_FALSE(isStructured(cfg, branchJoins(cfg)));
}
