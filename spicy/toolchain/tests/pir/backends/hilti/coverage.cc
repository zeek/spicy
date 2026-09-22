// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <spicy/compiler/detail/pir/backends/hilti/coverage.h>
#include <spicy/compiler/detail/pir/ir/verifier.h>

using namespace spicy::detail::pir;
using namespace spicy::detail::pir::ir;
using namespace spicy::detail::pir::backend::hilti;

namespace {

/** Builds the canonical one-byte-field parser package this backend accepts. */
struct OneBytePackage {
    Package package;
    TypeDeclId unit;
    DeclId field;
    FunctionId function;
};

OneBytePackage makeOneByte(const std::string& name = "OneByte") {
    OneBytePackage s;
    s.unit = s.package.createUnitDecl(name);
    s.field = s.package.createFieldDecl(s.unit, "value", s.package.uint8Type());

    auto state_type = s.package.parserStateType();
    auto unit_type = s.package.unitType(s.unit);
    s.function = s.package.createParserFunction(s.unit, state_type, unit_type);
    auto block = s.package.createBlock(s.package.function(s.function).root_region);

    auto state0 = s.package.addArgument(s.function, block, 0);
    auto unit0 = s.package.addUnitCreate(block, s.unit);
    auto read = s.package.addReadInteger(block,
                                         state0,
                                         ReadIntegerPayload{
                                             .width = 8,
                                             .signedness = Signedness::Unsigned,
                                             .byte_order = ByteOrder::Network,
                                         });
    auto state1 = s.package.addTupleGet(block, read, 0);
    auto value = s.package.addTupleGet(block, read, 1);
    auto unit1 = s.package.addPublishField(block, unit0, value, s.field);
    s.package.addParserFinish(block, state1, unit1);

    s.package.addParserRoot(s.unit, s.function);
    return s;
}

} // namespace

TEST_SUITE_BEGIN("PIR HILTI backend coverage");

TEST_CASE("the canonical one-byte package is supported") {
    auto sample = makeOneByte();
    REQUIRE(verify(sample.package).empty());
    CHECK(checkCoverage(sample.package).empty());
}

TEST_CASE("two same-named units in different roots are each supported") {
    Package package;
    auto unit_a = package.createUnitDecl("Same");
    auto field_a = package.createFieldDecl(unit_a, "value", package.uint8Type());
    auto unit_b = package.createUnitDecl("Same");
    auto field_b = package.createFieldDecl(unit_b, "value", package.uint8Type());

    auto state_type = package.parserStateType();

    auto build_root = [&](TypeDeclId unit, DeclId field) {
        auto unit_type = package.unitType(unit);
        auto fn = package.createParserFunction(unit, state_type, unit_type);
        auto block = package.createBlock(package.function(fn).root_region);
        auto state0 = package.addArgument(fn, block, 0);
        auto unit0 = package.addUnitCreate(block, unit);
        auto read = package.addReadInteger(block,
                                           state0,
                                           ReadIntegerPayload{
                                               .width = 8,
                                               .signedness = Signedness::Unsigned,
                                               .byte_order = ByteOrder::Network,
                                           });
        auto state1 = package.addTupleGet(block, read, 0);
        auto value = package.addTupleGet(block, read, 1);
        auto unit1 = package.addPublishField(block, unit0, value, field);
        package.addParserFinish(block, state1, unit1);
        package.addParserRoot(unit, fn);
    };

    build_root(unit_a, field_a);
    build_root(unit_b, field_b);

    REQUIRE(verify(package).empty());
    CHECK(checkCoverage(package).empty());
}

TEST_CASE("a package with no parser root is unsupported") {
    Package package;
    package.createFunction("free", package.voidType());

    CHECK_FALSE(checkCoverage(package).empty());
}

TEST_CASE("a package with a procedural function alongside a parser root is unsupported as a whole") {
    auto sample = makeOneByte();
    sample.package.createFunction("procedural", sample.package.voidType());

    auto features = checkCoverage(sample.package);
    REQUIRE_FALSE(features.empty());
}

TEST_CASE("a two-field unit is unsupported even once both fields publish") {
    Package package;
    auto unit = package.createUnitDecl("TwoFields");
    auto field_a = package.createFieldDecl(unit, "a", package.uint8Type());
    auto field_b = package.createFieldDecl(unit, "b", package.uint8Type());

    auto state_type = package.parserStateType();
    auto unit_type = package.unitType(unit);
    auto fn = package.createParserFunction(unit, state_type, unit_type);
    auto block = package.createBlock(package.function(fn).root_region);
    auto state0 = package.addArgument(fn, block, 0);
    auto unit0 = package.addUnitCreate(block, unit);
    auto read_a = package.addReadInteger(block,
                                         state0,
                                         ReadIntegerPayload{
                                             .width = 8,
                                             .signedness = Signedness::Unsigned,
                                             .byte_order = ByteOrder::Network,
                                         });
    auto state1 = package.addTupleGet(block, read_a, 0);
    auto value_a = package.addTupleGet(block, read_a, 1);
    auto unit1 = package.addPublishField(block, unit0, value_a, field_a);
    auto read_b = package.addReadInteger(block,
                                         state1,
                                         ReadIntegerPayload{
                                             .width = 8,
                                             .signedness = Signedness::Unsigned,
                                             .byte_order = ByteOrder::Network,
                                         });
    auto state2 = package.addTupleGet(block, read_b, 0);
    auto value_b = package.addTupleGet(block, read_b, 1);
    auto unit2 = package.addPublishField(block, unit1, value_b, field_b);
    package.addParserFinish(block, state2, unit2);
    package.addParserRoot(unit, fn);

    REQUIRE(verify(package).empty());
    CHECK_FALSE(checkCoverage(package).empty());
}

TEST_CASE("an unsupported read-integer width produces a coverage gap") {
    auto sample = makeOneByte();
    auto block = BlockId{0};
    auto read = InstId{2}; // %2 = parser.read_integer in the canonical sequence above
    sample.package.replaceInst(read,
                               Opcode::ReadInteger,
                               {InstId{0}},
                               ReadIntegerPayload{
                                   .width = 16,
                                   .signedness = Signedness::Unsigned,
                                   .byte_order = ByteOrder::Network,
                               });
    (void)block;

    CHECK_FALSE(checkCoverage(sample.package).empty());
}

TEST_CASE("repeated coverage checks of equivalent packages agree") {
    auto a = makeOneByte();
    auto b = makeOneByte();
    CHECK_EQ(checkCoverage(a.package).size(), checkCoverage(b.package).size());
    CHECK(checkCoverage(a.package).empty());
    CHECK(checkCoverage(b.package).empty());
}

TEST_SUITE_END();
