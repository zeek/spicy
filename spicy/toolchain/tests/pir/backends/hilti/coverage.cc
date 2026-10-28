// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <spicy/compiler/detail/pir/backends/hilti/coverage.h>
#include <spicy/compiler/detail/pir/ir/builder.h>
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
    auto builder = s.package.builder();
    s.unit = builder.createUnitDecl(name);
    s.field = builder.createFieldDecl(s.unit, "value", builder.uint8Type());

    auto state_type = builder.parserStateType();
    auto unit_type = builder.unitType(s.unit);
    s.function = builder.createParserFunction(s.unit, state_type, unit_type);
    auto block = builder.createBlock(s.package.function(s.function).root_region);

    auto state0 = builder.addArgument(s.function, block, 0);
    auto unit0 = builder.addUnitCreate(block, s.unit);
    auto read = builder.addReadInteger(block,
                                       state0,
                                       ReadIntegerPayload{
                                           .width = 8,
                                           .signedness = Signedness::Unsigned,
                                           .byte_order = ByteOrder::Network,
                                       });
    auto state1 = builder.addTupleGet(block, read, 0);
    auto value = builder.addTupleGet(block, read, 1);
    auto unit1 = builder.addPublishField(block, unit0, value, s.field);
    builder.addParserFinish(block, state1, unit1);

    builder.addParserRoot(s.unit, s.function);
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
    auto builder = package.builder();
    auto unit_a = builder.createUnitDecl("Same");
    auto field_a = builder.createFieldDecl(unit_a, "value", builder.uint8Type());
    auto unit_b = builder.createUnitDecl("Same");
    auto field_b = builder.createFieldDecl(unit_b, "value", builder.uint8Type());

    auto state_type = builder.parserStateType();

    auto build_root = [&](TypeDeclId unit, DeclId field) {
        auto unit_type = builder.unitType(unit);
        auto fn = builder.createParserFunction(unit, state_type, unit_type);
        auto block = builder.createBlock(package.function(fn).root_region);
        auto state0 = builder.addArgument(fn, block, 0);
        auto unit0 = builder.addUnitCreate(block, unit);
        auto read = builder.addReadInteger(block,
                                           state0,
                                           ReadIntegerPayload{
                                               .width = 8,
                                               .signedness = Signedness::Unsigned,
                                               .byte_order = ByteOrder::Network,
                                           });
        auto state1 = builder.addTupleGet(block, read, 0);
        auto value = builder.addTupleGet(block, read, 1);
        auto unit1 = builder.addPublishField(block, unit0, value, field);
        builder.addParserFinish(block, state1, unit1);
        builder.addParserRoot(unit, fn);
    };

    build_root(unit_a, field_a);
    build_root(unit_b, field_b);

    REQUIRE(verify(package).empty());
    CHECK(checkCoverage(package).empty());
}

TEST_CASE("a package with no parser root is unsupported") {
    Package package;
    auto builder = package.builder();
    builder.createFunction("free", builder.voidType());

    CHECK_FALSE(checkCoverage(package).empty());
}

TEST_CASE("a package with a procedural function alongside a parser root is unsupported as a whole") {
    auto sample = makeOneByte();
    auto builder = sample.package.builder();
    builder.createFunction("procedural", builder.voidType());

    auto features = checkCoverage(sample.package);
    REQUIRE_FALSE(features.empty());
}

TEST_CASE("a two-field unit is covered once both fields publish") {
    Package package;
    auto builder = package.builder();
    auto unit = builder.createUnitDecl("TwoFields");
    auto field_a = builder.createFieldDecl(unit, "a", builder.uint8Type());
    auto field_b = builder.createFieldDecl(unit, "b", builder.uint8Type());

    auto state_type = builder.parserStateType();
    auto unit_type = builder.unitType(unit);
    auto fn = builder.createParserFunction(unit, state_type, unit_type);
    auto block = builder.createBlock(package.function(fn).root_region);
    auto state0 = builder.addArgument(fn, block, 0);
    auto unit0 = builder.addUnitCreate(block, unit);
    auto read_a = builder.addReadInteger(block,
                                         state0,
                                         ReadIntegerPayload{
                                             .width = 8,
                                             .signedness = Signedness::Unsigned,
                                             .byte_order = ByteOrder::Network,
                                         });
    auto state1 = builder.addTupleGet(block, read_a, 0);
    auto value_a = builder.addTupleGet(block, read_a, 1);
    auto unit1 = builder.addPublishField(block, unit0, value_a, field_a);
    auto read_b = builder.addReadInteger(block,
                                         state1,
                                         ReadIntegerPayload{
                                             .width = 8,
                                             .signedness = Signedness::Unsigned,
                                             .byte_order = ByteOrder::Network,
                                         });
    auto state2 = builder.addTupleGet(block, read_b, 0);
    auto value_b = builder.addTupleGet(block, read_b, 1);
    auto unit2 = builder.addPublishField(block, unit1, value_b, field_b);
    builder.addParserFinish(block, state2, unit2);
    builder.addParserRoot(unit, fn);

    REQUIRE(verify(package).empty());
    CHECK(checkCoverage(package).empty());
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

TEST_CASE("a published vector of tuples is unsupported as storage") {
    Package package;
    auto builder = package.builder();
    auto unit = builder.createUnitDecl("Tuples");
    auto element = builder.tupleType({builder.uint8Type(), builder.uint8Type()});
    auto field = builder.createFieldDecl(unit, "items", builder.vectorType(element));
    auto fn = builder.createParserFunction(unit, builder.parserStateType(), builder.unitType(unit));
    auto block = builder.createBlock(package.function(fn).root_region);
    auto state = builder.addArgument(fn, block, 0);
    auto root = builder.addUnitCreate(block, unit);
    auto items = builder.addVectorEmpty(block, element);
    auto completed = builder.addPublishField(block, root, items, field);
    builder.addParserFinish(block, state, completed);
    builder.addParserRoot(unit, fn);

    REQUIRE(verify(package).empty());
    CHECK_FALSE(checkCoverage(package).empty());
}

TEST_CASE("repeated coverage checks of equivalent packages agree") {
    auto a = makeOneByte();
    auto b = makeOneByte();
    CHECK_EQ(checkCoverage(a.package).size(), checkCoverage(b.package).size());
    CHECK(checkCoverage(a.package).empty());
    CHECK(checkCoverage(b.package).empty());
}

TEST_SUITE_END();

namespace {

// A public function whose body passes a local to a native `inout` function and returns it.
void makeInoutRoot(Package& package) {
    auto builder = package.builder();
    auto bump =
        builder.createForeignFunction("bump", "::bump", {builder.placeType(builder.int64Type())}, builder.voidType());
    auto fn = builder.createFunction("scaled", {builder.int64Type()}, builder.int64Type());
    auto block = builder.createBlock(package.function(fn).root_region);
    auto arg = builder.addArgument(fn, block, 0);
    auto place = builder.addLocalPlace(block, arg);
    builder.addOpaqueOp(block, bump, {place});
    builder.addReturn(block, builder.addLoad(block, place));
    builder.addFunctionRoot(fn);
}

} // namespace

TEST_CASE("an ordinary function root with a native inout call is supported") {
    Package package;
    makeInoutRoot(package);

    REQUIRE(verify(package).empty());
    CHECK(checkCoverage(package).empty());
}

TEST_CASE("an ordinary function root with an opaque signature whose lifecycle is undeclared is unsupported") {
    Package package;
    auto builder = package.builder();
    OpaqueTypeInfo info;
    info.cxx_name = "::Handle";
    auto handle = builder.opaqueType(builder.createOpaqueTypeDecl("Handle", info));
    auto fn = builder.createFunction("passthrough", {handle}, handle);
    auto block = builder.createBlock(package.function(fn).root_region);
    builder.addReturn(block, builder.addArgument(fn, block, 0));
    builder.addFunctionRoot(fn);

    CHECK_FALSE(checkCoverage(package).empty());
}

TEST_CASE("branches that rejoin, including past an early return, are supported and crossing ones are not") {
    // `closes_after_return` joins its arms at the block after the inner return; `crossing` reaches the same two
    // returning blocks from both arms.
    auto build = [](const char* shape) {
        Package package;
        auto builder = package.builder();
        auto fn = builder.createFunction("pick", {builder.boolType()}, builder.int64Type());
        auto region = package.function(fn).root_region;
        auto b0 = builder.createBlock(region);
        auto b1 = builder.createBlock(region);
        auto b2 = builder.createBlock(region);
        auto b3 = builder.createBlock(region);
        auto b4 = builder.createBlock(region);
        auto flag = builder.addArgument(fn, b0, 0);
        builder.addBranch(b0, flag, b1, b2);
        std::string_view name = shape;
        if ( name == "diamond" ) {
            builder.addJump(b1, b3);
            builder.addJump(b2, b3);
            builder.addJump(b3, b4);
            builder.addReturn(b4, builder.addConstant(b4, 2));
        }
        else if ( name == "closes_after_return" ) {
            builder.addBranch(b1, flag, b3, b4);
            builder.addJump(b2, b4);
            builder.addReturn(b3, builder.addConstant(b3, 1));
            builder.addReturn(b4, builder.addConstant(b4, 2));
        }
        else {
            builder.addBranch(b1, flag, b3, b4);
            builder.addBranch(b2, flag, b3, b4);
            builder.addReturn(b3, builder.addConstant(b3, 1));
            builder.addReturn(b4, builder.addConstant(b4, 2));
        }
        builder.addFunctionRoot(fn);
        return package;
    };

    for ( const char* shape : {"diamond", "closes_after_return"} ) {
        auto package = build(shape);
        CHECK(verify(package).empty());
        CHECK(checkCoverage(package).empty());
    }

    auto crossing = build("crossing");
    CHECK(verify(crossing).empty());
    CHECK_FALSE(checkCoverage(crossing).empty());
}
