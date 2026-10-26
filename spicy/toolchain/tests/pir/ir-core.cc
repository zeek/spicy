// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <algorithm>
#include <limits>

#include <spicy/compiler/detail/pir/ir/builder.h>
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

TEST_CASE("verifier rejects a function whose region has more than one block") {
    Package package;
    auto builder = package.builder();
    auto fn = builder.createFunction("bad", builder.int64Type());
    auto region = package.function(fn).root_region;
    auto first = builder.createBlock(region);
    builder.createBlock(region);
    auto c = builder.addConstant(first, 1);
    builder.addReturn(first, c);

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
