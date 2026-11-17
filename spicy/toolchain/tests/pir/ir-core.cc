// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <algorithm>
#include <limits>

#include <spicy/compiler/detail/pir/analyses/field-use.h>
#include <spicy/compiler/detail/pir/ir/builder.h>
#include <spicy/compiler/detail/pir/ir/cfg.h>
#include <spicy/compiler/detail/pir/ir/package.h>
#include <spicy/compiler/detail/pir/ir/printer.h>
#include <spicy/compiler/detail/pir/ir/verifier.h>
#include <spicy/compiler/detail/pir/passes/constant-fold.h>

using namespace spicy::detail::pir::ir;
using namespace spicy::detail::pir::passes;

namespace {

bool hasInternalError(const std::vector<InternalError>& errors, std::string_view tag) {
    return std::ranges::any_of(errors, [tag](const InternalError& e) { return e.tag == tag; });
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
    auto c40 = builder.addIntConstant(block, builder.int64Type(), 40);
    auto c2 = builder.addIntConstant(block, builder.int64Type(), 2);
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
    "      %0 = core.int_constant 40 : int64\n"
    "      %1 = core.int_constant 2 : int64\n"
    "      %2 = core.add %0, %1 : int64\n"
    "      %3: core.return %2 : void\n";

const char* expected_folded =
    "type %0: void\n"
    "type %1: int64\n"
    "function %0 \"main\" -> int64:\n"
    "  region %0:\n"
    "    block %0:\n"
    "      %0 = core.int_constant 40 : int64\n"
    "      %1 = core.int_constant 2 : int64\n"
    "      %2 = core.int_constant 42 : int64\n"
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
    auto max = builder.addIntConstant(block, builder.int64Type(), std::numeric_limits<int64_t>::max());
    auto one = builder.addIntConstant(block, builder.int64Type(), 1);
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
    auto c = builder.addIntConstant(block, builder.int64Type(), 1);
    auto add = builder.addInstForTesting(block, Opcode::Add, {c}, builder.int64Type());
    builder.addReturn(block, add);

    CHECK(hasInternalError(verify(package), "operand-count-mismatch"));
    CHECK_FALSE(foldConstants(package, fn));
    CHECK_EQ(package.inst(add).opcode, Opcode::Add);
}

TEST_CASE("verifier rejects an invalid operand ID") {
    Package package;
    auto builder = package.builder();
    auto fn = builder.createFunction("bad", builder.int64Type());
    auto block = builder.createBlock(package.function(fn).root_region);
    auto c = builder.addIntConstant(block, builder.int64Type(), 1);
    auto bogus = InstId{999};
    auto add = builder.addInstForTesting(block, Opcode::Add, {c, bogus}, builder.int64Type());
    builder.addReturn(block, add);

    auto diags = verify(package);
    CHECK(hasInternalError(diags, "invalid-operand-id"));
}

TEST_CASE("verifier rejects an operand type mismatch") {
    Package package;
    auto builder = package.builder();
    auto fn = builder.createFunction("bad", builder.int64Type());
    auto block = builder.createBlock(package.function(fn).root_region);
    auto c = builder.addIntConstant(block, builder.int64Type(), 1);
    auto bad_void =
        builder.addInstForTesting(block, Opcode::IntConstant, {}, builder.voidType(), InstPayload(IntegerLiteral{0}));
    auto add = builder.addAdd(block, c, bad_void);
    builder.addReturn(block, add);

    auto diags = verify(package);
    CHECK(hasInternalError(diags, "operand-type-mismatch"));
}

TEST_CASE("verifier rejects a return value that doesn't match the function's result type") {
    Package package;
    auto builder = package.builder();
    auto fn = builder.createFunction("bad", builder.int64Type());
    auto block = builder.createBlock(package.function(fn).root_region);
    auto c =
        builder.addInstForTesting(block, Opcode::IntConstant, {}, builder.voidType(), InstPayload(IntegerLiteral{0}));
    builder.addReturn(block, c);

    auto diags = verify(package);
    CHECK(hasInternalError(diags, "return-type-mismatch"));
}

TEST_CASE("verifier rejects an unattached region and differentiates it from an empty package") {
    auto empty = makeSample();
    CHECK(verify(empty.package).empty());

    auto sample = makeSample();
    sample.package.builder().createRegion();
    auto diags = verify(sample.package);
    CHECK(hasInternalError(diags, "orphan-regions"));

    CHECK_NE(print(sample.package), print(empty.package));
}

TEST_CASE("verifier rejects a parser function whose body has no block") {
    Package package;
    auto builder = package.builder();
    auto unit = builder.createUnitDecl("Unit");
    builder.createParserFunction(unit, builder.parserStateType(), builder.unitType(unit));

    auto diags = verify(package);
    CHECK(hasInternalError(diags, "region-block-count-mismatch"));
}

TEST_CASE("verifier rejects an ordinary function whose region has no block") {
    Package package;
    auto builder = package.builder();
    builder.createFunction("bad", builder.int64Type());

    auto diags = verify(package);
    CHECK(hasInternalError(diags, "region-block-count-mismatch"));
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
    CHECK(hasInternalError(diags, "unrecognized-opcode"));
}

TEST_CASE("verifier rejects an instruction after the block terminator") {
    Package package;
    auto builder = package.builder();
    auto fn = builder.createFunction("bad", builder.int64Type());
    auto block = builder.createBlock(package.function(fn).root_region);
    auto c = builder.addIntConstant(block, builder.int64Type(), 1);
    builder.addReturn(block, c);
    builder.addIntConstant(block, builder.int64Type(), 2);

    auto diags = verify(package);
    CHECK(hasInternalError(diags, "terminator-not-last"));
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

    CHECK(hasInternalError(verify(package), "repeat-requires-bound"));

    package.replaceInst(yield, Opcode::Yield, {body_state, body_state});
    CHECK(hasInternalError(verify(package), "invalid-yield"));
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

    CHECK(hasInternalError(verify(package), "invalid-yield"));
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

    CHECK(hasInternalError(verify(package), "invalid-region-argument"));
}

TEST_CASE("uint8 and parser.state intern deterministically and are stable across repeated requests") {
    Package package;
    auto builder = package.builder();
    auto uint8_1 = builder.uint8Type();
    auto uint8_2 = builder.uint8Type();
    CHECK_EQ(uint8_1, uint8_2);
    CHECK_EQ(package.type(uint8_1).kind, TypeKind::Integer);

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
    CHECK(hasInternalError(diags, "type-missing-declaration"));
}

TEST_CASE("verifier rejects an invalid tuple element type without asserting") {
    Package package;
    package.builder().tupleType({TypeId{999}});

    auto diags = verify(package);
    CHECK(hasInternalError(diags, "type-invalid-type-argument"));
}

TEST_CASE("verifier rejects a field with an invalid owner or type without asserting") {
    Package package;
    auto builder = package.builder();
    auto unit_decl = builder.createUnitDecl("OneByte");
    builder.createFieldDecl(unit_decl, "value", TypeId{999});

    auto diags = verify(package);
    CHECK(hasInternalError(diags, "invalid-field-type"));
}

TEST_CASE("regular expressions intern by patterns and flags") {
    Package package;
    auto builder = package.builder();
    auto a = builder.internRegExp({RegExpPattern{.value = "A*"}}, true);
    CHECK_EQ(builder.internRegExp({RegExpPattern{.value = "A*"}}, true), a);
    CHECK_NE(builder.internRegExp({RegExpPattern{.value = "A*"}}, false), a);
    CHECK_NE(builder.internRegExp({RegExpPattern{.value = "A*", .case_insensitive = true}}, true), a);
    CHECK_NE(builder.internRegExp({RegExpPattern{.value = "A*", .id = 3}}, true), a);
    CHECK_NE(builder.internRegExp({RegExpPattern{.value = "A*"}, RegExpPattern{.value = "B"}}, true), a);
    CHECK_EQ(package.regexps().size(), 5);
    CHECK(verify(package).empty());
}

TEST_CASE("regular expressions print with their patterns and flags") {
    Package package;
    auto builder = package.builder();
    builder.internRegExp({RegExpPattern{.value = "A*"}}, true);
    builder.internRegExp({RegExpPattern{.value = "a", .case_insensitive = true}, RegExpPattern{.value = "b", .id = 7}},
                         false);
    auto dump = print(package);
    CHECK_NE(dump.find("regexp %0: /A*/ nosub\n"), std::string::npos);
    CHECK_NE(dump.find("regexp %1: /a/i | /b/#7\n"), std::string::npos);
}

TEST_CASE("verifier rejects a regular expression without patterns") {
    Package package;
    package.builder().internRegExp({}, true);
    CHECK(hasInternalError(verify(package), "regexp-empty"));
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
    auto arg = builder.addIntConstant(block, builder.int64Type(), 7);
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

    CHECK(hasInternalError(verify(package), "opaque-op-argument-type-mismatch"));
}

TEST_CASE("verifier rejects a foreign call with the wrong argument count") {
    Package package;
    auto builder = package.builder();
    auto consume = builder.createForeignFunction("consume", "::consume", {builder.int64Type()}, builder.int64Type());

    auto fn = builder.createFunction("caller", builder.int64Type());
    auto block = builder.createBlock(package.function(fn).root_region);
    auto result = builder.addOpaqueOp(block, consume, {});
    builder.addReturn(block, result);

    CHECK(hasInternalError(verify(package), "opaque-op-argument-count-mismatch"));
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

    CHECK(hasInternalError(verify(package), "opaque-op-result-type-mismatch"));
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

    CHECK(hasInternalError(verify(package), "opaque-op-invalid-payload"));
}

TEST_CASE("verifier rejects an opaque declaration without a native name or lifecycle") {
    Package package;
    auto builder = package.builder();
    builder.createOpaqueTypeDecl("Unnamed", OpaqueTypeInfo{.lifecycle = OpaqueLifecycle{}});
    builder.createOpaqueTypeDecl("Undeclared", OpaqueTypeInfo{.cxx_name = "::Undeclared"});

    CHECK(hasInternalError(verify(package), "opaque-declaration-incomplete"));
}

TEST_CASE("verifier rejects a foreign function without a binding or with a void parameter") {
    Package package;
    auto builder = package.builder();
    builder.createForeignFunction("unbound", "", {builder.int64Type()}, builder.int64Type());
    builder.createForeignFunction("void", "::void_arg", {builder.voidType()}, builder.int64Type());

    auto diags = verify(package);
    CHECK(hasInternalError(diags, "foreign-function-missing-binding"));
    CHECK(hasInternalError(diags, "foreign-function-invalid-parameter"));
}

TEST_CASE("verifier accepts a foreign function that takes an affine value by value") {
    Package package;
    auto builder = package.builder();
    auto vector = builder.vectorType(builder.int64Type());
    builder.createForeignFunction("take", "::take", {vector}, builder.int64Type());

    auto diags = verify(package);
    CHECK_FALSE(hasInternalError(diags, "foreign-function-invalid-parameter"));
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
    auto one = builder.addIntConstant(increment_block, builder.int64Type(), 1);
    builder.addReturn(increment_block, builder.addAdd(increment_block, x, one));

    auto fn = builder.createFunction("caller", builder.int64Type());
    auto block = builder.createBlock(package.function(fn).root_region);
    auto place = builder.addLocalPlace(block, builder.addIntConstant(block, builder.int64Type(), 5));
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
    auto place = builder.addLocalPlace(block, builder.addIntConstant(block, builder.int64Type(), 1));
    auto byte =
        builder.addInstForTesting(block, Opcode::IntConstant, {}, builder.uint8Type(), InstPayload(IntegerLiteral{2}));
    builder.addStore(block, place, byte);
    builder.addReturn(block, builder.addLoad(block, place));

    CHECK(hasInternalError(verify(package), "store-value-type-mismatch"));
}

TEST_CASE("verifier rejects a load and a store whose operand is not a place") {
    Package package;
    auto builder = package.builder();
    auto fn = builder.createFunction("bad", builder.int64Type());
    auto block = builder.createBlock(package.function(fn).root_region);
    auto not_a_place = builder.addIntConstant(block, builder.int64Type(), 1);
    auto loaded = builder.addLoad(block, not_a_place);
    builder.addStore(block, not_a_place, loaded);
    builder.addReturn(block, loaded);

    CHECK(hasInternalError(verify(package), "place-operand-mismatch"));
}

TEST_CASE("verifier rejects a call to a parser function") {
    Package package;
    auto builder = package.builder();
    auto unit = builder.createUnitDecl("Unit");
    auto parser = builder.createParserFunction(unit, builder.parserStateType(), builder.unitType(unit));

    auto fn = builder.createFunction("caller", builder.int64Type());
    auto block = builder.createBlock(package.function(fn).root_region);
    builder.addReturn(block, builder.addCall(block, parser, {}));

    CHECK(hasInternalError(verify(package), "call-target-not-normal"));
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

    CHECK(hasInternalError(verify(package), "call-argument-count-mismatch"));
}

TEST_CASE("verifier rejects a place stored in a tuple or returned from a function") {
    Package package;
    auto builder = package.builder();
    auto place = builder.placeType(builder.int64Type());
    builder.tupleType({place});

    auto fn = builder.createFunction("returns_place", place);
    auto block = builder.createBlock(package.function(fn).root_region);
    builder.addInstForTesting(block, Opcode::IntConstant, {}, place, InstPayload(IntegerLiteral{0}));
    builder.addInstForTesting(block, Opcode::Return, {}, place);

    auto diags = verify(package);
    CHECK(hasInternalError(diags, "place-escapes"));
}

TEST_CASE("verifier rejects a local place initialized with a void value") {
    Package package;
    auto builder = package.builder();
    auto fn = builder.createFunction("bad", builder.int64Type());
    auto block = builder.createBlock(package.function(fn).root_region);
    auto void_value =
        builder.addInstForTesting(block, Opcode::IntConstant, {}, builder.voidType(), InstPayload(IntegerLiteral{0}));
    builder.addLocalPlace(block, void_value);
    builder.addReturn(block, builder.addIntConstant(block, builder.int64Type(), 0));

    CHECK(hasInternalError(verify(package), "local-place-invalid-initial"));
}

TEST_CASE("verifier rejects a function root that is not an ordinary function") {
    Package package;
    auto builder = package.builder();
    auto unit = builder.createUnitDecl("Unit");
    builder.addFunctionRoot(builder.createParserFunction(unit, builder.parserStateType(), builder.unitType(unit)));

    CHECK(hasInternalError(verify(package), "function-root-not-normal"));
}

TEST_CASE("verifier rejects a function root that references no function") {
    Package package;
    package.builder().addFunctionRoot(FunctionId{999});

    CHECK(hasInternalError(verify(package), "invalid-function-root"));
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
    auto value = builder.addIntConstant(block, builder.int64Type(), 1);
    builder.addInstForTesting(block, Opcode::Tuple, {value}, builder.tupleType({builder.uint8Type()}));
    builder.addReturnVoid(block);

    CHECK(hasInternalError(verify(package), "tuple-result-type-mismatch"));
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
    builder.addOpaqueOp(block, show, {builder.addIntConstant(block, builder.int64Type(), 1)});
    builder.addOpaqueOp(block, show, {builder.addBoolConstant(block, false)});
    builder.addOpaqueOp(block, show_pointer, {builder.addIntConstant(block, builder.int64Type(), 3)});
    builder.addOpaqueOp(block,
                        show_tuple,
                        {builder.addTuple(block, {builder.addIntConstant(block, builder.int64Type(), 2)})});
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
    bad_builder.addOpaqueOp(bad_block, tuple_only, {bad_builder.addIntConstant(bad_block, bad_builder.int64Type(), 1)});
    bad_builder.addReturnVoid(bad_block);

    CHECK(hasInternalError(verify(bad), "opaque-op-argument-type-mismatch"));
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

    CHECK(hasInternalError(verify(package), "opaque-load-requires-copyable"));
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
    CHECK(hasInternalError(verify(package), "invalid-operand-id"));

    auto foreign = builder.createFunction("foreign", builder.int64Type());
    auto foreign_block = builder.createBlock(package.function(foreign).root_region);
    builder.addReturn(foreign_block, builder.addCall(foreign_block, callee, {callee_arg}));
    CHECK(hasInternalError(verify(package), "operand-not-same-block"));

    Package cyclic;
    auto cyclic_builder = cyclic.builder();
    auto cyclic_callee =
        cyclic_builder.createFunction("callee", {cyclic_builder.int64Type()}, cyclic_builder.int64Type());
    auto cyclic_callee_block = cyclic_builder.createBlock(cyclic.function(cyclic_callee).root_region);
    cyclic_builder.addReturn(cyclic_callee_block, cyclic_builder.addArgument(cyclic_callee, cyclic_callee_block, 0));

    auto fn = cyclic_builder.createFunction("caller", cyclic_builder.int64Type());
    auto block = cyclic_builder.createBlock(cyclic.function(fn).root_region);
    auto constant = cyclic_builder.addIntConstant(block, cyclic_builder.int64Type(), 42);
    auto call = cyclic_builder.addCall(block, cyclic_callee, {constant});
    cyclic.replaceInst(constant, Opcode::Call, {call}, FunctionPayload{cyclic_callee});
    cyclic_builder.addReturn(block, call);
    CHECK(hasInternalError(verify(cyclic), "operand-used-before-definition"));
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

    CHECK(hasInternalError(verify(package), "field-place-unit-mismatch"));
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
    CHECK(hasInternalError(diags, "field-place-result-type-mismatch"));
    CHECK(hasInternalError(diags, "field-place-invalid-payload"));
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
    auto base = builder.addIntConstant(entry, builder.int64Type(), 40);
    builder.addBranch(entry, flag, then_block, else_block);

    builder.addJump(then_block, join);
    builder.addJump(else_block, join);

    builder.addReturn(join, builder.addAdd(join, base, builder.addIntConstant(join, builder.int64Type(), 2)));

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
    builder.addReturn(then_block, builder.addIntConstant(then_block, builder.int64Type(), 1));
    builder.addReturn(else_block, builder.addIntConstant(else_block, builder.int64Type(), 2));

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

    builder.addBranch(entry, builder.addIntConstant(entry, builder.int64Type(), 1), then_block, else_block);
    builder.addReturn(then_block, builder.addIntConstant(then_block, builder.int64Type(), 1));
    builder.addReturn(else_block, builder.addIntConstant(else_block, builder.int64Type(), 2));

    CHECK(hasInternalError(verify(package), "operand-type-mismatch"));
}

TEST_CASE("verifier rejects a successor that belongs to another function body") {
    Package package;
    auto builder = package.builder();
    auto other = builder.createFunction("other", builder.int64Type());
    auto other_block = builder.createBlock(package.function(other).root_region);
    builder.addReturn(other_block, builder.addIntConstant(other_block, builder.int64Type(), 1));

    auto fn = builder.createFunction("bad", builder.int64Type());
    auto entry = builder.createBlock(package.function(fn).root_region);
    builder.addJump(entry, other_block);

    CHECK(hasInternalError(verify(package), "invalid-successor"));
}

namespace {

// A loop that appends to a vector Phi: `pre` writes the empty vector, `body` appends and writes it again, and `head`
// leaves for `exit` or `body`. The tests below change which Upsilons it has.
struct VectorLoop {
    Package package;
    FunctionId fn;
    BlockId pre, head, body, exit;
    InstId phi, empty, next;

    VectorLoop(bool preheader_write, int latch_writes) {
        auto builder = package.builder();
        fn = builder.createFunction("loop", builder.voidType());
        auto region = package.function(fn).root_region;
        pre = builder.createBlock(region);
        head = builder.createBlock(region);
        body = builder.createBlock(region);
        exit = builder.createBlock(region);

        empty = builder.addVectorEmpty(pre, builder.int64Type());
        phi = builder.addPhi(head, package.inst(empty).result_type);
        if ( preheader_write )
            builder.addUpsilon(pre, empty, phi);
        builder.addJump(pre, head);

        builder.addBranch(head, builder.addBoolConstant(head, true), body, exit);
        next = builder.addVectorAppend(body, phi, builder.addIntConstant(body, builder.int64Type(), 1));
        for ( int i = 0; i < latch_writes; ++i )
            builder.addUpsilon(body, next, phi);
        builder.addJump(body, head);

        builder.addCall(exit, dropper(), {phi});
        builder.addReturnVoid(exit);
    }

    FunctionId dropper() {
        auto builder = package.builder();
        auto drop = builder.createFunction("drop",
                                           {Parameter(package.inst(empty).result_type, ParameterMode::Take)},
                                           builder.voidType());
        auto block = builder.createBlock(package.function(drop).root_region);
        builder.addArgument(drop, block, 0);
        builder.addReturnVoid(block);
        return drop;
    }
};

} // namespace

TEST_CASE("a loop's header Phi merges the preheader's and the latch's values, and each iteration consumes it once") {
    VectorLoop loop(true, 1);
    CHECK(verify(loop.package).empty());
}

TEST_CASE("verifier rejects a loop header Phi without an Upsilon in the preheader") {
    VectorLoop loop(false, 1);
    CHECK(hasInternalError(verify(loop.package), "phi-shadow-unset"));
}

TEST_CASE("verifier rejects two Upsilons on the latch path of one Phi") {
    VectorLoop loop(true, 2);
    CHECK(hasInternalError(verify(loop.package), "phi-shadow-overwritten"));
}

TEST_CASE("verifier rejects a loop that never writes the Phi's shadow from the latch") {
    VectorLoop loop(true, 0);
    CHECK(hasInternalError(verify(loop.package), "phi-shadow-unset"));
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
    auto only_on_then = builder.addIntConstant(then_block, builder.int64Type(), 1);
    builder.addJump(then_block, join);
    builder.addJump(else_block, join);
    builder.addReturn(join, only_on_then);

    CHECK(hasInternalError(verify(package), "operand-not-same-block"));
}

TEST_CASE("core.equal compares two integers or two bools of one type and yields a bool") {
    Package package;
    auto builder = package.builder();
    auto fn = builder.createFunction("compare", builder.int64Type());
    auto block = builder.createBlock(package.function(fn).root_region);
    builder.addEqual(block,
                     builder.addIntConstant(block, builder.int64Type(), 1),
                     builder.addIntConstant(block, builder.int64Type(), 2));
    builder.addEqual(block, builder.addBoolConstant(block, true), builder.addBoolConstant(block, false));
    builder.addReturn(block, builder.addIntConstant(block, builder.int64Type(), 0));

    CHECK(verify(package).empty());
    CHECK(print(package).find("core.equal") != std::string::npos);
}

TEST_CASE("verifier rejects core.equal on operands of different or non-comparable types") {
    Package package;
    auto builder = package.builder();
    auto fn = builder.createFunction("bad", builder.int64Type());
    auto block = builder.createBlock(package.function(fn).root_region);
    builder.addEqual(block,
                     builder.addIntConstant(block, builder.int64Type(), 1),
                     builder.addBoolConstant(block, true));
    builder.addEqual(block, builder.addBytesConstant(block, "a"), builder.addBytesConstant(block, "a"));
    builder.addReturn(block, builder.addIntConstant(block, builder.int64Type(), 0));

    CHECK(hasInternalError(verify(package), "equal-operand-type-mismatch"));
}

TEST_CASE("verifier rejects a jump inside a structured region") {
    Package package;
    auto builder = package.builder();
    auto unit = builder.createUnitDecl("Unit");
    auto fn = builder.createParserFunction(unit, builder.parserStateType(), builder.unitType(unit));
    auto block = builder.createBlock(package.function(fn).root_region);
    auto state = builder.addArgument(fn, block, 0);
    auto self = builder.addUnitCreate(block, unit);
    auto bounded = builder.addEnterBound(block, state, builder.addIntConstant(block, builder.uint64Type(), 1));
    auto body = builder.createRegion();
    auto body_block = builder.createBlock(body);
    builder.addRegionArgument(body_block, 0, builder.parserStateType());
    builder.addJump(body_block, body_block);
    auto repeated = builder.addRepeatToBound(block, {bounded}, body);
    builder.addParserFinish(block, builder.addLeaveBound(block, builder.addTupleGet(block, repeated, 0)), self);

    CHECK(hasInternalError(verify(package), "control-flow-outside-function-body"));
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
    builder.addVectorAppend(then_block, vector, builder.addIntConstant(then_block, builder.int64Type(), 1));
    builder.addReturnVoid(then_block);
    builder.addVectorAppend(else_block, vector, builder.addIntConstant(else_block, builder.int64Type(), 2));
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
    builder.addVectorAppend(then_block, vector, builder.addIntConstant(then_block, builder.int64Type(), 1));
    builder.addJump(then_block, join);
    builder.addVectorAppend(join, vector, builder.addIntConstant(join, builder.int64Type(), 2));
    builder.addReturnVoid(join);

    CHECK(hasInternalError(verify(package), "parser-state-reused"));
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
    builder.addReturn(join, builder.addIntConstant(join, builder.int64Type(), 0));

    auto cfg = buildCfg(package, region);
    auto ipdom = immediatePostDominators(cfg);
    CHECK(ipdom[0].kind == PostDominator::Kind::Block);
    CHECK(ipdom[0].position == 3);
    CHECK(ipdom[3].kind == PostDominator::Kind::Exit);
}

TEST_CASE("postorder follows successors in order, tolerates cycles, and omits unreachable positions") {
    // 0 -> {1, 2}, 1 -> 0 (a cycle), 2 -> {}, and 3 is unreachable from 0.
    std::vector<std::vector<size_t>> successors = {{1, 2}, {0}, {}, {0}};
    CHECK(postorder(successors, 0) == std::vector<size_t>{1, 2, 0});
    CHECK(postorder({{1}, {0}}, 0) == std::vector<size_t>{1, 0});
}

namespace {

// A parser that has read one byte and is about to publish it.
struct ReleaseSample {
    Package package;
    TypeDeclId unit;
    DeclId field;
    FunctionId fn;
    BlockId block;
    InstId state;
    InstId next;
    InstId value;
};

ReleaseSample makeReleaseSample() {
    ReleaseSample s;
    auto builder = s.package.builder();
    s.unit = builder.createUnitDecl("Root");
    s.field = builder.createFieldDecl(s.unit, "value", builder.uint8Type());
    s.fn = builder.createParserFunction(s.unit, builder.parserStateType(), builder.unitType(s.unit));
    s.block = builder.createBlock(s.package.function(s.fn).root_region);
    s.state = builder.addArgument(s.fn, s.block, 0);
    auto read = builder.addReadInteger(s.block,
                                       s.state,
                                       ReadIntegerPayload{
                                           .width = 8,
                                           .signedness = Signedness::Unsigned,
                                           .byte_order = ByteOrder::Network,
                                       });
    s.next = builder.addTupleGet(s.block, read, 0);
    s.value = builder.addTupleGet(s.block, read, 1);
    builder.addParserRoot(s.unit, s.fn);
    return s;
}

} // namespace

TEST_CASE("releasing input yields the next parser state") {
    auto s = makeReleaseSample();
    auto builder = s.package.builder();
    auto released = builder.addReleaseInput(s.block, s.next);
    auto root = builder.addUnitCreate(s.block, s.unit);
    auto completed = builder.addPublishField(s.block, root, s.value, s.field);
    builder.addParserFinish(s.block, released, completed);

    CHECK(s.package.inst(released).opcode == Opcode::ReleaseInput);
    CHECK(s.package.type(s.package.inst(released).result_type).kind == TypeKind::ParserState);
    CHECK(verify(s.package).empty());
}

TEST_CASE("verifier rejects reading from a parser state after it was released") {
    auto s = makeReleaseSample();
    auto builder = s.package.builder();
    builder.addReleaseInput(s.block, s.next);
    auto root = builder.addUnitCreate(s.block, s.unit);
    auto completed = builder.addPublishField(s.block, root, s.value, s.field);
    builder.addParserFinish(s.block, s.next, completed);

    CHECK(hasInternalError(verify(s.package), "parser-state-reused"));
}

TEST_CASE("verifier rejects releasing input of something that is not a parser state") {
    auto s = makeReleaseSample();
    auto builder = s.package.builder();
    auto released = builder.addReleaseInput(s.block, s.value);
    auto root = builder.addUnitCreate(s.block, s.unit);
    auto completed = builder.addPublishField(s.block, root, s.value, s.field);
    builder.addParserFinish(s.block, released, completed);

    CHECK(hasInternalError(verify(s.package), "operand-type-mismatch"));
}

TEST_CASE("releasing input keeps the state's byte bound") {
    Package package;
    auto builder = package.builder();
    auto unit = builder.createUnitDecl("Root");
    auto field = builder.createFieldDecl(unit, "value", builder.uint8Type());
    auto fn = builder.createParserFunction(unit, builder.parserStateType(), builder.unitType(unit));
    auto block = builder.createBlock(package.function(fn).root_region);
    auto state = builder.addArgument(fn, block, 0);
    auto length = builder.addReadInteger(block,
                                         state,
                                         ReadIntegerPayload{
                                             .width = 64,
                                             .signedness = Signedness::Unsigned,
                                             .byte_order = ByteOrder::Network,
                                         });
    auto bounded =
        builder.addEnterBound(block, builder.addTupleGet(block, length, 0), builder.addTupleGet(block, length, 1));
    auto released = builder.addReleaseInput(block, bounded);
    auto read = builder.addReadInteger(block,
                                       released,
                                       ReadIntegerPayload{
                                           .width = 8,
                                           .signedness = Signedness::Unsigned,
                                           .byte_order = ByteOrder::Network,
                                       });
    auto unbounded = builder.addLeaveBound(block, builder.addTupleGet(block, read, 0));
    auto root = builder.addUnitCreate(block, unit);
    auto completed = builder.addPublishField(block, root, builder.addTupleGet(block, read, 1), field);
    builder.addParserFinish(block, unbounded, completed);
    builder.addParserRoot(unit, fn);

    CHECK(verify(package).empty());
}

TEST_CASE("leaving a bound needs a state that is still bounded after a release") {
    auto s = makeReleaseSample();
    auto builder = s.package.builder();
    auto released = builder.addReleaseInput(s.block, s.next);
    auto unbounded = builder.addLeaveBound(s.block, released);
    auto root = builder.addUnitCreate(s.block, s.unit);
    auto completed = builder.addPublishField(s.block, root, s.value, s.field);
    builder.addParserFinish(s.block, unbounded, completed);

    CHECK(hasInternalError(verify(s.package), "invalid-parser-operation"));
}

TEST_CASE("integer types intern by width and signedness") {
    Package package;
    auto builder = package.builder();
    CHECK_EQ(builder.integerType(64, Signedness::Signed), builder.int64Type());
    CHECK_EQ(builder.integerType(8, Signedness::Unsigned), builder.uint8Type());
    CHECK_EQ(builder.integerType(64, Signedness::Unsigned), builder.uint64Type());

    auto u16 = builder.integerType(16, Signedness::Unsigned);
    auto i16 = builder.integerType(16, Signedness::Signed);
    CHECK_NE(u16, i16);
    CHECK_EQ(builder.integerType(16, Signedness::Unsigned), u16);
    CHECK_EQ(package.type(i16).integer, IntegerType{.width = 16, .signedness = Signedness::Signed});
    CHECK_EQ(typeName(package, i16), "int16");
    CHECK_EQ(typeName(package, builder.integerType(32, Signedness::Unsigned)), "uint32");
}

TEST_CASE("verifier rejects an integer type of an unsupported width") {
    Package package;
    auto builder = package.builder();
    builder.integerType(24, Signedness::Unsigned);
    CHECK(hasInternalError(verify(package), "type-invalid-integer"));
}

namespace {

// A function that adds two constants of `type` and returns the sum.
struct Addition {
    Package package;
    FunctionId function;
    InstId add;
};

Addition makeAddition(uint8_t width, Signedness signedness, uint64_t lhs, uint64_t rhs) {
    Addition a;
    auto builder = a.package.builder();
    auto type = builder.integerType(width, signedness);
    a.function = builder.createFunction("f", type);
    auto block = builder.createBlock(a.package.function(a.function).root_region);
    a.add = builder.addAdd(block, builder.addIntConstant(block, type, lhs), builder.addIntConstant(block, type, rhs));
    builder.addReturn(block, a.add);
    return a;
}

std::optional<uint64_t> folded(Addition& a) {
    REQUIRE(verify(a.package).empty());
    foldConstants(a.package, a.function);
    REQUIRE(verify(a.package).empty());
    const auto& inst = a.package.inst(a.add);
    if ( inst.opcode != Opcode::IntConstant )
        return {};
    return std::get<IntegerLiteral>(inst.payload).bits;
}

} // namespace

TEST_CASE("constant folding adds every integer width when the sum fits") {
    for ( uint8_t width : {8, 16, 32, 64} ) {
        auto max = truncateBits(UINT64_MAX, width);
        auto unsigned_sum = makeAddition(width, Signedness::Unsigned, max - 1, 1);
        CHECK_EQ(folded(unsigned_sum), max);

        auto unsigned_overflow = makeAddition(width, Signedness::Unsigned, max, 1);
        CHECK_FALSE(folded(unsigned_overflow));

        // -1 + -1 is -2, which is all ones but the lowest bit.
        auto signed_sum = makeAddition(width, Signedness::Signed, max, max);
        CHECK_EQ(folded(signed_sum), max - 1);

        auto signed_max = truncateBits(UINT64_MAX, width - 1);
        auto signed_overflow = makeAddition(width, Signedness::Signed, signed_max, 1);
        CHECK_FALSE(folded(signed_overflow));

        auto signed_min = signed_max + 1;
        auto signed_underflow = makeAddition(width, Signedness::Signed, signed_min, max);
        CHECK_FALSE(folded(signed_underflow));
    }
}

TEST_CASE("constant folding compares constants of one type") {
    Package package;
    auto builder = package.builder();
    auto fn = builder.createFunction("f", builder.boolType());
    auto block = builder.createBlock(package.function(fn).root_region);
    auto u16 = builder.integerType(16, Signedness::Unsigned);
    auto same = builder.addEqual(block, builder.addIntConstant(block, u16, 7), builder.addIntConstant(block, u16, 7));
    auto different =
        builder.addEqual(block, builder.addIntConstant(block, u16, 7), builder.addIntConstant(block, u16, 8));
    auto bools = builder.addEqual(block, builder.addBoolConstant(block, true), builder.addBoolConstant(block, false));
    auto nested = builder.addEqual(block, same, different);
    builder.addReturn(block, nested);

    REQUIRE(verify(package).empty());
    CHECK(foldConstants(package, fn));
    REQUIRE(verify(package).empty());
    for ( auto [id, value] : {std::pair{same, true}, {different, false}, {bools, false}, {nested, false}} ) {
        REQUIRE_EQ(package.inst(id).opcode, Opcode::BoolConstant);
        CHECK_EQ(std::get<BoolLiteral>(package.inst(id).payload).value, value);
    }
}

namespace {

// An ordinary function `f(bool) -> T` whose body is a diamond: `entry` branches to `then` or `else`, which both
// jump to `join`. Tests add the merge.
struct Diamond {
    Package package;
    FunctionId function;
    BlockId entry;
    BlockId then_;
    BlockId else_;
    BlockId join;
    InstId condition;
};

Diamond makeDiamond() {
    Diamond d;
    auto builder = d.package.builder();
    auto result = builder.int64Type();
    d.function = builder.createFunction("f", std::vector<Parameter>{builder.boolType()}, result);
    auto region = d.package.function(d.function).root_region;
    d.entry = builder.createBlock(region);
    d.then_ = builder.createBlock(region);
    d.else_ = builder.createBlock(region);
    d.join = builder.createBlock(region);
    d.condition = builder.addArgument(d.function, d.entry, 0);
    return d;
}

void closeDiamond(Diamond& d) {
    auto builder = d.package.builder();
    builder.addBranch(d.entry, d.condition, d.then_, d.else_);
    builder.addJump(d.then_, d.join);
    builder.addJump(d.else_, d.join);
}

} // namespace

TEST_CASE("a Phi merges the values that Upsilons write on both arms of a diamond") {
    auto d = makeDiamond();
    auto builder = d.package.builder();
    auto phi = builder.addPhi(d.join, builder.int64Type());
    builder.addUpsilon(d.then_, builder.addIntConstant(d.then_, builder.int64Type(), 1), phi);
    builder.addUpsilon(d.else_, builder.addIntConstant(d.else_, builder.int64Type(), 2), phi);
    closeDiamond(d);
    builder.addReturn(d.join, phi);

    CHECK(verify(d.package).empty());
    CHECK_NE(print(d.package).find("core.upsilon %"), std::string::npos);
    CHECK_NE(print(d.package).find("^%" + std::to_string(phi.index)), std::string::npos);
}

TEST_CASE("verifier rejects a Phi that a path reaches without writing its shadow") {
    auto d = makeDiamond();
    auto builder = d.package.builder();
    auto phi = builder.addPhi(d.join, builder.int64Type());
    builder.addUpsilon(d.then_, builder.addIntConstant(d.then_, builder.int64Type(), 1), phi);
    closeDiamond(d);
    builder.addReturn(d.join, phi);

    CHECK(hasInternalError(verify(d.package), "phi-shadow-unset"));
}

TEST_CASE("verifier rejects an Upsilon that writes a shadow before the earlier write was read") {
    auto d = makeDiamond();
    auto builder = d.package.builder();
    auto phi = builder.addPhi(d.join, builder.int64Type());
    // The entry writes the shadow, and the then-arm writes it again before the Phi reads it.
    builder.addUpsilon(d.entry, builder.addIntConstant(d.entry, builder.int64Type(), 0), phi);
    builder.addUpsilon(d.then_, builder.addIntConstant(d.then_, builder.int64Type(), 1), phi);
    closeDiamond(d);
    builder.addReturn(d.join, phi);

    auto errors = verify(d.package);
    CHECK(hasInternalError(errors, "phi-shadow-overwritten"));
    CHECK_FALSE(hasInternalError(errors, "phi-shadow-unset"));
}

TEST_CASE("a Phi reads its shadow where it sits, which a later Upsilon may write again") {
    auto d = makeDiamond();
    auto builder = d.package.builder();
    auto phi = builder.addPhi(d.join, builder.int64Type());
    builder.addUpsilon(d.then_, builder.addIntConstant(d.then_, builder.int64Type(), 1), phi);
    builder.addUpsilon(d.else_, builder.addIntConstant(d.else_, builder.int64Type(), 2), phi);
    closeDiamond(d);
    // After the Phi has read the shadow, writing it again is no double write.
    builder.addUpsilon(d.join, phi, phi);
    builder.addReturn(d.join, phi);
    CHECK(verify(d.package).empty());
}

TEST_CASE("a Phi need not lead its block or have its Upsilons in predecessors") {
    auto d = makeDiamond();
    auto builder = d.package.builder();
    auto phi = builder.addPhi(d.then_, builder.int64Type());
    // The entry writes the shadow, and only the then-arm reads it.
    builder.addUpsilon(d.entry, builder.addIntConstant(d.entry, builder.int64Type(), 7), phi);
    auto sum = builder.addAdd(d.then_, phi, builder.addIntConstant(d.then_, builder.int64Type(), 1));
    builder.addLocalPlace(d.then_, sum);
    closeDiamond(d);
    builder.addReturn(d.join, builder.addIntConstant(d.join, builder.int64Type(), 0));
    CHECK(verify(d.package).empty());
}

TEST_CASE("verifier rejects a Phi that runs before any Upsilon writes its shadow") {
    Package package;
    auto builder = package.builder();
    auto fn = builder.createFunction("f", builder.int64Type());
    auto block = builder.createBlock(package.function(fn).root_region);
    auto phi = builder.addPhi(block, builder.int64Type());
    builder.addUpsilon(block, builder.addIntConstant(block, builder.int64Type(), 1), phi);
    builder.addReturn(block, phi);
    CHECK(hasInternalError(verify(package), "phi-shadow-unset"));
}

TEST_CASE("verifier rejects an Upsilon whose target is not a Phi of its function or has another type") {
    auto d = makeDiamond();
    auto builder = d.package.builder();
    auto phi = builder.addPhi(d.join, builder.int64Type());
    auto one = builder.addIntConstant(d.then_, builder.int64Type(), 1);
    builder.addUpsilon(d.then_, one, phi);
    builder.addUpsilon(d.else_, builder.addBoolConstant(d.else_, true), phi);
    closeDiamond(d);
    builder.addReturn(d.join, phi);
    CHECK(hasInternalError(verify(d.package), "upsilon-type-mismatch"));

    auto other = makeDiamond();
    auto ob = other.package.builder();
    auto not_phi = ob.addIntConstant(other.entry, ob.int64Type(), 0);
    ob.addInstForTesting(other.then_,
                         Opcode::Upsilon,
                         {ob.addIntConstant(other.then_, ob.int64Type(), 1)},
                         ob.voidType(),
                         InstPayload(UpsilonPayload{not_phi}));
    closeDiamond(other);
    ob.addReturn(other.join, not_phi);
    CHECK(hasInternalError(verify(other.package), "upsilon-target-invalid"));

    // A Phi of another function is not a target either.
    Package two;
    auto tb = two.builder();
    auto f = tb.createFunction("f", tb.int64Type());
    auto f_block = tb.createBlock(two.function(f).root_region);
    auto foreign_phi = tb.addPhi(f_block, tb.int64Type());
    tb.addUpsilon(f_block, tb.addIntConstant(f_block, tb.int64Type(), 0), foreign_phi);
    tb.addReturn(f_block, foreign_phi);
    auto g = tb.createFunction("g", tb.int64Type());
    auto g_block = tb.createBlock(two.function(g).root_region);
    auto zero = tb.addIntConstant(g_block, tb.int64Type(), 0);
    tb.addUpsilon(g_block, zero, foreign_phi);
    tb.addReturn(g_block, zero);
    CHECK(hasInternalError(verify(two), "upsilon-target-invalid"));
}

TEST_CASE("verifier rejects a Phi of void type") {
    Package package;
    auto builder = package.builder();
    auto fn = builder.createFunction("f", builder.voidType());
    auto block = builder.createBlock(package.function(fn).root_region);
    builder.addPhi(block, builder.voidType());
    builder.addReturnVoid(block);
    CHECK(hasInternalError(verify(package), "phi-invalid-type"));
}

TEST_CASE("an affine value written by an Upsilon on each arm is consumed once per path") {
    auto d = makeDiamond();
    auto builder = d.package.builder();
    auto vector_type = builder.vectorType(builder.int64Type());
    // `f` returns an int64; the merged vector is only consumed by a store into a local.
    auto phi = builder.addPhi(d.join, vector_type);
    auto vector = builder.addVectorEmpty(d.entry, builder.int64Type());
    builder.addUpsilon(d.then_, vector, phi);
    builder.addUpsilon(d.else_,
                       builder.addVectorAppend(d.else_,
                                               vector,
                                               builder.addIntConstant(d.else_, builder.int64Type(), 1)),
                       phi);
    closeDiamond(d);
    builder.addLocalPlace(d.join, phi);
    builder.addReturn(d.join, builder.addIntConstant(d.join, builder.int64Type(), 0));
    CHECK(verify(d.package).empty());

    // Consuming the same version twice on one arm is a reuse.
    auto twice = makeDiamond();
    auto tb = twice.package.builder();
    auto twice_phi = tb.addPhi(twice.join, vector_type);
    auto twice_vector = tb.addVectorEmpty(twice.entry, tb.int64Type());
    tb.addUpsilon(twice.then_, twice_vector, twice_phi);
    tb.addLocalPlace(twice.then_, twice_vector);
    tb.addUpsilon(twice.else_, tb.addVectorEmpty(twice.else_, tb.int64Type()), twice_phi);
    closeDiamond(twice);
    tb.addLocalPlace(twice.join, twice_phi);
    tb.addReturn(twice.join, tb.addIntConstant(twice.join, tb.int64Type(), 0));
    CHECK(hasInternalError(verify(twice.package), "parser-state-reused"));
}

TEST_CASE("Phi and Upsilon have shadow effects") {
    CHECK(effectsFor(Opcode::Phi).reads_shadow);
    CHECK_FALSE(effectsFor(Opcode::Phi).writes_shadow);
    CHECK(effectsFor(Opcode::Upsilon).writes_shadow);
    CHECK_FALSE(schemaFor(Opcode::Phi)->is_pure);
    CHECK_FALSE(schemaFor(Opcode::Upsilon)->is_pure);
}

namespace {

// A parser for a unit with fields `tag` (uint8) and `value` (uint8) that switches on the tag: tag 1 publishes `value`
// in its own block, tag 2 shares the default's block, which publishes nothing. Both reach `join`, which merges the
// parser state and unit and finishes.
struct Switched {
    Package package;
    TypeDeclId unit;
    DeclId tag;
    DeclId value;
    FunctionId function;
    BlockId entry;
    BlockId one;
    BlockId other;
    BlockId join;
    InstId control;
    InstId state;
    InstId self;
    InstId state_phi;
    InstId unit_phi;
};

Switched makeSwitched(bool constant_control = false, bool finish = true) {
    Switched s;
    auto builder = s.package.builder();
    s.unit = builder.createUnitDecl("U");
    s.tag = builder.createFieldDecl(s.unit, "tag", builder.uint8Type());
    s.value = builder.createFieldDecl(s.unit, "value", builder.uint8Type());
    s.function = builder.createParserFunction(s.unit, builder.parserStateType(), builder.unitType(s.unit));
    auto region = s.package.function(s.function).root_region;
    s.entry = builder.createBlock(region);
    s.one = builder.createBlock(region);
    s.other = builder.createBlock(region);
    s.join = builder.createBlock(region);

    auto state = builder.addArgument(s.function, s.entry, 0);
    auto created = builder.addUnitCreate(s.entry, s.unit);
    auto read = builder.addReadInteger(s.entry, state, ReadIntegerPayload{.width = 8});
    s.state = builder.addTupleGet(s.entry, read, 0);
    auto tag = builder.addTupleGet(s.entry, read, 1);
    s.self = builder.addPublishField(s.entry, created, tag, s.tag);
    s.control = constant_control ? builder.addIntConstant(s.entry, builder.uint8Type(), 1) : tag;

    s.state_phi = builder.addPhi(s.join, builder.parserStateType());
    s.unit_phi = builder.addPhi(s.join, builder.unitType(s.unit));
    if ( finish )
        builder.addParserFinish(s.join, s.state_phi, s.unit_phi);
    builder.addParserRoot(s.unit, s.function);
    return s;
}

void addSwitch(Switched& s, std::vector<SwitchCase> cases) {
    s.package.builder().addSwitch(s.entry,
                                  s.control,
                                  SwitchPayload{.cases = std::move(cases), .default_target = s.other});
}

// How the other arm is malformed, if at all.
enum class OtherArm { Valid, NoStateUpsilon, FreshUnit, ConsumeTwice, OneWithoutState };

// Tag 1 reads and publishes `value`; the other arm passes its state and unit through.
void fillArms(Switched& s, OtherArm other = OtherArm::Valid) {
    auto builder = s.package.builder();
    auto read = builder.addReadInteger(s.one, s.state, ReadIntegerPayload{.width = 8});
    auto unit = builder.addPublishField(s.one, s.self, builder.addTupleGet(s.one, read, 1), s.value);
    if ( other != OtherArm::OneWithoutState )
        builder.addUpsilon(s.one, builder.addTupleGet(s.one, read, 0), s.state_phi);
    builder.addUpsilon(s.one, unit, s.unit_phi);
    builder.addJump(s.one, s.join);
    // The other arm consumes the state once to release input, and then once more when it merges.
    if ( other == OtherArm::ConsumeTwice )
        builder.addReleaseInput(s.other, s.state);
    if ( other != OtherArm::NoStateUpsilon )
        builder.addUpsilon(s.other, s.state, s.state_phi);
    builder.addUpsilon(s.other,
                       other == OtherArm::FreshUnit ? builder.addUnitCreate(s.other, s.unit) : s.self,
                       s.unit_phi);
    builder.addJump(s.other, s.join);
}

SwitchCase to(uint64_t value, BlockId target) { return SwitchCase{.value = IntegerLiteral{value}, .target = target}; }

} // namespace

TEST_CASE("a parser switches into arms whose Phis merge the state and unit at a join") {
    auto s = makeSwitched();
    addSwitch(s, {to(1, s.one), to(2, s.other)});
    fillArms(s);
    CHECK(verify(s.package).empty());
    CHECK_NE(print(s.package).find("core.switch %"), std::string::npos);
    CHECK_NE(print(s.package).find("1 -> %" + std::to_string(s.one.index) + ", 2 -> %" + std::to_string(s.other.index) +
                                   ", default -> %" + std::to_string(s.other.index)),
             std::string::npos);

    // A field published on only one arm is conditional; one published before the switch is always present.
    auto presence = spicy::detail::pir::analyses::fieldPresence(s.package);
    CHECK(presence.isConditional(s.value));
    CHECK_FALSE(presence.isConditional(s.tag));
}

TEST_CASE("a switch whose cases share a target writes a Phi's shadow once per path") {
    auto s = makeSwitched();
    addSwitch(s, {to(1, s.one), to(2, s.one)});
    fillArms(s);
    CHECK(verify(s.package).empty());

    // The shared arm forgets to merge the state.
    auto missing = makeSwitched();
    addSwitch(missing, {to(1, missing.one), to(2, missing.one)});
    fillArms(missing, OtherArm::OneWithoutState);
    auto errors = verify(missing.package);
    CHECK(hasInternalError(errors, "phi-shadow-unset"));
    CHECK_EQ(errors.size(), 1U);

    // The default arm forgets to merge the state.
    auto default_missing = makeSwitched();
    addSwitch(default_missing, {to(1, default_missing.one)});
    fillArms(default_missing, OtherArm::NoStateUpsilon);
    CHECK(hasInternalError(verify(default_missing.package), "phi-shadow-unset"));
}

TEST_CASE("verifier rejects switch cases that do not fit the operand or repeat a value") {
    auto range = makeSwitched();
    addSwitch(range, {to(256, range.one)});
    fillArms(range);
    CHECK(hasInternalError(verify(range.package), "switch-case-out-of-range"));

    auto twice = makeSwitched();
    addSwitch(twice, {to(1, twice.one), to(1, twice.other)});
    fillArms(twice);
    CHECK(hasInternalError(verify(twice.package), "switch-duplicate-case"));
}

TEST_CASE("an affine state consumed in two switch arms is fine, but twice in one arm is not") {
    // Each arm consumes the state that the switch's block produced, once.
    auto once = makeSwitched();
    addSwitch(once, {to(1, once.one)});
    fillArms(once);
    CHECK(verify(once.package).empty());

    auto twice = makeSwitched();
    addSwitch(twice, {to(1, twice.one)});
    fillArms(twice, OtherArm::ConsumeTwice);
    auto errors = verify(twice.package);
    CHECK(hasInternalError(errors, "parser-state-reused"));
    CHECK(std::ranges::all_of(errors, [](const auto& e) { return e.tag == "parser-state-reused"; }));
}

TEST_CASE("verifier rejects a Phi or Upsilon in a structured region, and a switch there") {
    Package package;
    auto builder = package.builder();
    auto unit = builder.createUnitDecl("Unit");
    auto fn = builder.createParserFunction(unit, builder.parserStateType(), builder.unitType(unit));
    auto block = builder.createBlock(package.function(fn).root_region);
    auto state = builder.addArgument(fn, block, 0);
    auto self = builder.addUnitCreate(block, unit);
    auto bounded = builder.addEnterBound(block, state, builder.addIntConstant(block, builder.uint64Type(), 1));
    auto body = builder.createRegion();
    auto body_block = builder.createBlock(body);
    auto body_state = builder.addRegionArgument(body_block, 0, builder.parserStateType());
    auto phi = builder.addPhi(body_block, builder.parserStateType());
    builder.addUpsilon(body_block, body_state, phi);
    builder.addSwitch(body_block,
                      builder.addIntConstant(body_block, builder.uint8Type(), 1),
                      SwitchPayload{.cases = {}, .default_target = body_block});
    auto repeated = builder.addRepeatToBound(block, {bounded}, body);
    builder.addParserFinish(block, builder.addLeaveBound(block, builder.addTupleGet(block, repeated, 0)), self);

    auto errors = verify(package);
    CHECK(hasInternalError(errors, "phi-outside-function-body"));
    CHECK(hasInternalError(errors, "control-flow-outside-function-body"));
}

TEST_CASE("verifier rejects a switch whose target belongs to another function body") {
    auto s = makeSwitched();
    addSwitch(s, {to(1, s.one)});
    fillArms(s);
    // A block id of the right range but in no region of this function.
    auto builder = s.package.builder();
    auto stray_region = builder.createRegion();
    auto stray = builder.createBlock(stray_region);
    auto& switch_inst = s.package.inst(s.package.block(s.entry).insts.back());
    auto payload = std::get<SwitchPayload>(switch_inst.payload);
    payload.cases[0].target = stray;
    s.package.replaceInst(s.package.block(s.entry).insts.back(), Opcode::Switch, switch_inst.args, payload);
    CHECK(hasInternalError(verify(s.package), "invalid-successor"));
}

TEST_CASE("verifier rejects a structured region with two blocks") {
    Package package;
    auto builder = package.builder();
    auto unit = builder.createUnitDecl("Unit");
    auto fn = builder.createParserFunction(unit, builder.parserStateType(), builder.unitType(unit));
    auto block = builder.createBlock(package.function(fn).root_region);
    auto state = builder.addArgument(fn, block, 0);
    auto self = builder.addUnitCreate(block, unit);
    auto bounded = builder.addEnterBound(block, state, builder.addIntConstant(block, builder.uint64Type(), 1));
    auto body = builder.createRegion();
    auto first = builder.createBlock(body);
    builder.addYield(first, {builder.addRegionArgument(first, 0, builder.parserStateType())});
    auto second = builder.createBlock(body);
    builder.addYield(second, {builder.addRegionArgument(second, 0, builder.parserStateType())});
    auto repeated = builder.addRepeatToBound(block, {bounded}, body);
    builder.addParserFinish(block, builder.addLeaveBound(block, builder.addTupleGet(block, repeated, 0)), self);

    CHECK(hasInternalError(verify(package), "region-block-count-mismatch"));
}

TEST_CASE("verifier rejects a Phi that merges units of two unit.create") {
    auto s = makeSwitched();
    addSwitch(s, {to(1, s.one)});
    fillArms(s, OtherArm::FreshUnit);
    CHECK(hasInternalError(verify(s.package), "unit-phi-mixed-origin"));
}

TEST_CASE("verifier reports a field published twice on one path through a switch") {
    auto s = makeSwitched(false, false);
    addSwitch(s, {to(1, s.one)});
    fillArms(s);
    // The join publishes `value` again, which the path through `one` already did.
    auto builder = s.package.builder();
    auto read = builder.addReadInteger(s.join, s.state_phi, ReadIntegerPayload{.width = 8});
    auto unit = builder.addPublishField(s.join, s.unit_phi, builder.addTupleGet(s.join, read, 1), s.value);
    builder.addParserFinish(s.join, builder.addTupleGet(s.join, read, 0), unit);
    auto errors = verify(s.package);
    CHECK(hasInternalError(errors, "duplicate-field-publication"));
}

TEST_CASE("constant folding turns a switch on a constant into a jump and erases the skipped arm") {
    auto s = makeSwitched(true);
    addSwitch(s, {to(1, s.one)});
    fillArms(s);
    REQUIRE(verify(s.package).empty());
    CHECK(spicy::detail::pir::analyses::fieldPresence(s.package).isConditional(s.value));

    CHECK(foldConstants(s.package, s.function));
    REQUIRE(verify(s.package).empty());
    const auto& terminator = s.package.inst(s.package.block(s.entry).insts.back());
    CHECK_EQ(terminator.opcode, Opcode::Jump);
    CHECK_EQ(std::get<JumpPayload>(terminator.payload).target, s.one);
    CHECK(s.package.isErased(s.other));
    CHECK(print(s.package).find("orphan") == std::string::npos);
    // Only one path finishes now, and it publishes the field.
    CHECK_FALSE(spicy::detail::pir::analyses::fieldPresence(s.package).isConditional(s.value));
}

TEST_CASE("constant folding turns a branch on a constant into a jump") {
    auto d = makeDiamond();
    auto builder = d.package.builder();
    auto phi = builder.addPhi(d.join, builder.int64Type());
    builder.addUpsilon(d.then_, builder.addIntConstant(d.then_, builder.int64Type(), 1), phi);
    builder.addUpsilon(d.else_, builder.addIntConstant(d.else_, builder.int64Type(), 2), phi);
    auto constant = builder.addBoolConstant(d.entry, false);
    builder.addBranch(d.entry, constant, d.then_, d.else_);
    builder.addJump(d.then_, d.join);
    builder.addJump(d.else_, d.join);
    builder.addReturn(d.join, phi);
    REQUIRE(verify(d.package).empty());

    CHECK(foldConstants(d.package, d.function));
    REQUIRE(verify(d.package).empty());
    CHECK(d.package.isErased(d.then_));
    CHECK_FALSE(d.package.isErased(d.else_));
}
