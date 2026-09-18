// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <algorithm>
#include <limits>

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
    auto fn = s.package.createFunction("main", s.package.int64Type());
    auto block = s.package.createBlock(s.package.function(fn).root_region);
    auto c40 = s.package.addConstant(block, 40);
    auto c2 = s.package.addConstant(block, 2);
    s.add = s.package.addAdd(block, c40, c2);
    s.package.addReturn(block, s.add);
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
    auto fn = package.createFunction("overflow", package.int64Type());
    auto block = package.createBlock(package.function(fn).root_region);
    auto max = package.addConstant(block, std::numeric_limits<int64_t>::max());
    auto one = package.addConstant(block, 1);
    auto add = package.addAdd(block, max, one);
    package.addReturn(block, add);

    CHECK(verify(package).empty());
    CHECK_FALSE(foldConstants(package, fn));
    CHECK_EQ(package.inst(add).opcode, Opcode::Add);
}

TEST_CASE("constant folding safely skips a core.add with too few operands") {
    Package package;
    auto fn = package.createFunction("bad", package.int64Type());
    auto block = package.createBlock(package.function(fn).root_region);
    auto c = package.addConstant(block, 1);
    auto add = package.addInstForTesting(block, Opcode::Add, {c}, package.int64Type());
    package.addReturn(block, add);

    CHECK(hasDiagnostic(verify(package), diag::OperandCountMismatch));
    CHECK_FALSE(foldConstants(package, fn));
    CHECK_EQ(package.inst(add).opcode, Opcode::Add);
}

TEST_CASE("verifier rejects an invalid operand ID") {
    Package package;
    auto fn = package.createFunction("bad", package.int64Type());
    auto block = package.createBlock(package.function(fn).root_region);
    auto c = package.addConstant(block, 1);
    auto bogus = InstId{999};
    auto add = package.addInstForTesting(block, Opcode::Add, {c, bogus}, package.int64Type());
    package.addReturn(block, add);

    auto diags = verify(package);
    CHECK(hasDiagnostic(diags, diag::InvalidOperandId));
}

TEST_CASE("verifier rejects an operand type mismatch") {
    Package package;
    auto fn = package.createFunction("bad", package.int64Type());
    auto block = package.createBlock(package.function(fn).root_region);
    auto c = package.addConstant(block, 1);
    auto bad_void =
        package.addInstForTesting(block, Opcode::Constant, {}, package.voidType(), InstPayload(Int64Literal{0}));
    auto add = package.addAdd(block, c, bad_void);
    package.addReturn(block, add);

    auto diags = verify(package);
    CHECK(hasDiagnostic(diags, diag::OperandTypeMismatch));
}

TEST_CASE("verifier rejects a return value that doesn't match the function's result type") {
    Package package;
    auto fn = package.createFunction("bad", package.int64Type());
    auto block = package.createBlock(package.function(fn).root_region);
    auto c = package.addInstForTesting(block, Opcode::Constant, {}, package.voidType(), InstPayload(Int64Literal{0}));
    package.addReturn(block, c);

    auto diags = verify(package);
    CHECK(hasDiagnostic(diags, diag::ReturnTypeMismatch));
}

TEST_CASE("verifier rejects an unattached region and differentiates it from an empty package") {
    auto empty = makeSample();
    CHECK(verify(empty.package).empty());

    auto sample = makeSample();
    sample.package.createRegion();
    auto diags = verify(sample.package);
    CHECK(hasDiagnostic(diags, diag::OrphanRegions));

    CHECK_NE(print(sample.package), print(empty.package));
}

TEST_CASE("verifier rejects a function whose region has more than one block") {
    Package package;
    auto fn = package.createFunction("bad", package.int64Type());
    auto region = package.function(fn).root_region;
    auto first = package.createBlock(region);
    package.createBlock(region);
    auto c = package.addConstant(first, 1);
    package.addReturn(first, c);

    auto diags = verify(package);
    CHECK(hasDiagnostic(diags, diag::RegionBlockCountMismatch));
}

TEST_CASE("verifier rejects an unrecognized opcode") {
    Package package;
    auto fn = package.createFunction("bad", package.int64Type());
    auto block = package.createBlock(package.function(fn).root_region);
    auto bogus_op = static_cast<Opcode>(99);
    auto c = package.addInstForTesting(block, bogus_op, {}, package.int64Type());
    package.addReturn(block, c);

    auto diags = verify(package);
    CHECK(hasDiagnostic(diags, diag::UnrecognizedOpcode));
}

TEST_CASE("verifier rejects an instruction after the block terminator") {
    Package package;
    auto fn = package.createFunction("bad", package.int64Type());
    auto block = package.createBlock(package.function(fn).root_region);
    auto c = package.addConstant(block, 1);
    package.addReturn(block, c);
    package.addConstant(block, 2);

    auto diags = verify(package);
    CHECK(hasDiagnostic(diags, diag::TerminatorNotLast));
}

TEST_CASE("uint8 and parser.state intern deterministically and are stable across repeated requests") {
    Package package;
    auto uint8_1 = package.uint8Type();
    auto uint8_2 = package.uint8Type();
    CHECK_EQ(uint8_1, uint8_2);
    CHECK_EQ(package.type(uint8_1).kind, TypeKind::UInt8);

    auto state_1 = package.parserStateType();
    auto state_2 = package.parserStateType();
    CHECK_EQ(state_1, state_2);
    CHECK_EQ(package.type(state_1).kind, TypeKind::ParserState);

    CHECK_NE(uint8_1, state_1);
}

TEST_CASE("unit and tuple types intern structurally and repeated requests return the same TypeId") {
    Package package;
    auto unit_decl = package.createUnitDecl("OneByte");

    auto unit_1 = package.unitType(unit_decl);
    auto unit_2 = package.unitType(unit_decl);
    CHECK_EQ(unit_1, unit_2);
    CHECK_EQ(package.type(unit_1).kind, TypeKind::Unit);
    CHECK_EQ(package.type(unit_1).declaration, unit_decl);

    auto uint8 = package.uint8Type();
    auto state = package.parserStateType();
    auto tuple_1 = package.tupleType({state, uint8});
    auto tuple_2 = package.tupleType({state, uint8});
    CHECK_EQ(tuple_1, tuple_2);
    CHECK_EQ(package.type(tuple_1).kind, TypeKind::Tuple);
    CHECK_EQ(package.type(tuple_1).type_arguments, std::vector<TypeId>{state, uint8});

    // Different element order is a different structural type.
    auto tuple_3 = package.tupleType({uint8, state});
    CHECK_NE(tuple_1, tuple_3);
}

TEST_CASE("two unit declarations with the same name remain distinct nominal types") {
    Package package;
    auto decl_a = package.createUnitDecl("Same");
    auto decl_b = package.createUnitDecl("Same");
    CHECK_NE(decl_a, decl_b);

    auto type_a = package.unitType(decl_a);
    auto type_b = package.unitType(decl_b);
    CHECK_NE(type_a, type_b);
}

TEST_CASE("procedural-only packages retain Step 2's exact canonical type numbering") {
    auto sample = makeSample();
    CHECK_EQ(sample.package.types().size(), 2);
    CHECK_EQ(sample.package.voidType(), TypeId{0});
    CHECK_EQ(sample.package.int64Type(), TypeId{1});
}

TEST_CASE("field declarations are appended to their owning unit in call order") {
    Package package;
    auto unit_decl = package.createUnitDecl("OneByte");
    auto uint8 = package.uint8Type();
    auto field_a = package.createFieldDecl(unit_decl, "a", uint8);
    auto field_b = package.createFieldDecl(unit_decl, "b", uint8);

    CHECK_EQ(package.typeDecl(unit_decl).fields, std::vector<DeclId>{field_a, field_b});
    CHECK_EQ(package.declaration(field_a).owner, unit_decl);
    CHECK_EQ(package.declaration(field_b).owner, unit_decl);
}

TEST_CASE("verifier rejects an invalid type declaration on a unit type without asserting") {
    Package package;
    // Deliberately malformed: no declared unit backs this type ID's declaration.
    auto unit_decl_placeholder = TypeDeclId{999};
    package.unitType(unit_decl_placeholder);

    auto diags = verify(package);
    CHECK(hasDiagnostic(diags, diag::TypeMissingDeclaration));
}

TEST_CASE("verifier rejects an invalid tuple element type without asserting") {
    Package package;
    package.tupleType({TypeId{999}});

    auto diags = verify(package);
    CHECK(hasDiagnostic(diags, diag::TypeInvalidTypeArgument));
}

TEST_CASE("verifier rejects a field with an invalid owner or type without asserting") {
    Package package;
    auto unit_decl = package.createUnitDecl("OneByte");
    package.createFieldDecl(unit_decl, "value", TypeId{999});

    auto diags = verify(package);
    CHECK(hasDiagnostic(diags, diag::InvalidFieldType));
}

TEST_SUITE_END();
