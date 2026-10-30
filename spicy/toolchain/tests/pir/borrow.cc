// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <algorithm>

#include <spicy/compiler/detail/pir/ir/builder.h>
#include <spicy/compiler/detail/pir/ir/package.h>
#include <spicy/compiler/detail/pir/ir/printer.h>
#include <spicy/compiler/detail/pir/ir/verifier.h>

using namespace spicy::detail::pir::ir;

namespace {

bool hasDiagnostic(const std::vector<Diagnostic>& diags, const DiagnosticDefinition& def) {
    return std::ranges::any_of(diags, [&def](const Diagnostic& d) { return d.definition == def; });
}

// A package with one unit of two integer fields, and the helpers that read, write, and consume it.
struct Cells {
    Package package;
    TypeDeclId unit;
    DeclId first;
    DeclId second;
    TypeId unit_type;

    Cells() {
        auto builder = package.builder();
        unit = builder.createUnitDecl("Cell");
        first = builder.createFieldDecl(unit, "first", builder.uint64Type());
        second = builder.createFieldDecl(unit, "second", builder.uint64Type());
        unit_type = builder.unitType(unit);
    }

    // `read(borrow unit) -> uint64` returns a field.
    FunctionId read() {
        auto builder = package.builder();
        auto fn = builder.createFunction("read", {Parameter(unit_type, ParameterMode::Borrow)}, builder.uint64Type());
        auto block = builder.createBlock(package.function(fn).root_region);
        auto cell = builder.addArgument(fn, block, 0);
        builder.addReturn(block, builder.addLoad(block, builder.addFieldPlace(block, cell, first)));
        return fn;
    }

    // `write(borrow_mut unit)` stores into a field.
    FunctionId write() {
        auto builder = package.builder();
        auto fn = builder.createFunction("write", {Parameter(unit_type, ParameterMode::BorrowMut)}, builder.voidType());
        auto block = builder.createBlock(package.function(fn).root_region);
        auto cell = builder.addArgument(fn, block, 0);
        builder.addStore(block, builder.addFieldPlace(block, cell, first), builder.addUint64Constant(block, 7));
        builder.addReturnVoid(block);
        return fn;
    }

    // `take(unit)` owns the unit it receives.
    FunctionId take() {
        auto builder = package.builder();
        auto fn = builder.createFunction("take", {Parameter(unit_type, ParameterMode::Take)}, builder.voidType());
        auto block = builder.createBlock(package.function(fn).root_region);
        builder.addArgument(fn, block, 0);
        builder.addReturnVoid(block);
        return fn;
    }

    // A function that owns a unit, for the callers below to use.
    FunctionId owner(const std::string& name = "owner") {
        auto builder = package.builder();
        return builder.createFunction(name, {Parameter(unit_type, ParameterMode::Take)}, builder.voidType());
    }
};

} // namespace

TEST_SUITE_BEGIN("PIR borrowed parameters");

TEST_CASE("a borrowed unit can be read and written, repeatedly, by callers that keep ownership") {
    Cells s;
    auto builder = s.package.builder();
    auto read = s.read();
    auto write = s.write();

    auto fn = s.owner();
    auto block = builder.createBlock(s.package.function(fn).root_region);
    auto cell = builder.addArgument(fn, block, 0);
    builder.addCall(block, read, {cell});
    builder.addCall(block, write, {cell});
    builder.addCall(block, read, {cell});
    builder.addCall(block, read, {cell});
    builder.addReturnVoid(block);

    CHECK(verify(s.package).empty());
    auto dump = print(s.package);
    CHECK(dump.find("(borrow unit<@%0 \"Cell\">) -> uint64") != std::string::npos);
    CHECK(dump.find("(borrow_mut unit<@%0 \"Cell\">) -> void") != std::string::npos);
}

TEST_CASE("a borrowed unit's field read is independent of the borrow and can be returned") {
    Cells s;
    CHECK(verify((s.read(), s.package)).empty());
}

TEST_CASE("a writable borrow can be forwarded as a read borrow, but a read borrow cannot be upgraded") {
    Cells s;
    auto builder = s.package.builder();
    auto read = s.read();
    auto write = s.write();

    auto forward_down =
        builder.createFunction("down", {Parameter(s.unit_type, ParameterMode::BorrowMut)}, builder.voidType());
    auto down_block = builder.createBlock(s.package.function(forward_down).root_region);
    auto down_cell = builder.addArgument(forward_down, down_block, 0);
    builder.addCall(down_block, read, {down_cell});
    builder.addCall(down_block, write, {down_cell});
    builder.addReturnVoid(down_block);
    CHECK(verify(s.package).empty());

    auto forward_up = builder.createFunction("up", {Parameter(s.unit_type, ParameterMode::Borrow)}, builder.voidType());
    auto up_block = builder.createBlock(s.package.function(forward_up).root_region);
    auto up_cell = builder.addArgument(forward_up, up_block, 0);
    builder.addCall(up_block, write, {up_cell});
    builder.addReturnVoid(up_block);
    CHECK(hasDiagnostic(verify(s.package), diag::BorrowWriteDenied));
}

TEST_CASE("an assignment through a field place derived from a read borrow is rejected") {
    Cells s;
    auto builder = s.package.builder();
    auto fn = builder.createFunction("bad", {Parameter(s.unit_type, ParameterMode::Borrow)}, builder.voidType());
    auto block = builder.createBlock(s.package.function(fn).root_region);
    auto cell = builder.addArgument(fn, block, 0);
    // The store passes the type check: the place holds a uint64, and so does the value.
    builder.addStore(block, builder.addFieldPlace(block, cell, s.second), builder.addUint64Constant(block, 1));
    builder.addReturnVoid(block);

    CHECK(hasDiagnostic(verify(s.package), diag::BorrowWriteDenied));
}

TEST_CASE("a scalar borrowed through a place follows the same write permission") {
    Package package;
    auto builder = package.builder();
    auto place = builder.placeType(builder.int64Type());

    auto set = builder.createFunction("set", {Parameter(place, ParameterMode::BorrowMut)}, builder.voidType());
    auto set_block = builder.createBlock(package.function(set).root_region);
    builder.addStore(set_block, builder.addArgument(set, set_block, 0), builder.addConstant(set_block, 3));
    builder.addReturnVoid(set_block);

    auto get = builder.createFunction("get", {Parameter(place, ParameterMode::Borrow)}, builder.int64Type());
    auto get_block = builder.createBlock(package.function(get).root_region);
    builder.addReturn(get_block, builder.addLoad(get_block, builder.addArgument(get, get_block, 0)));
    CHECK(verify(package).empty());

    auto bad = builder.createFunction("bad", {Parameter(place, ParameterMode::Borrow)}, builder.voidType());
    auto bad_block = builder.createBlock(package.function(bad).root_region);
    auto bad_place = builder.addArgument(bad, bad_block, 0);
    builder.addCall(bad_block, set, {bad_place});
    builder.addReturnVoid(bad_block);
    CHECK(hasDiagnostic(verify(package), diag::BorrowWriteDenied));
}

TEST_CASE("a caller can lend its local storage, and sees the callee's write") {
    Package package;
    auto builder = package.builder();
    auto place = builder.placeType(builder.int64Type());

    auto set = builder.createFunction("set", {Parameter(place, ParameterMode::BorrowMut)}, builder.voidType());
    auto set_block = builder.createBlock(package.function(set).root_region);
    builder.addStore(set_block, builder.addArgument(set, set_block, 0), builder.addConstant(set_block, 3));
    builder.addReturnVoid(set_block);

    auto fn = builder.createFunction("caller", builder.int64Type());
    auto block = builder.createBlock(package.function(fn).root_region);
    auto local = builder.addLocalPlace(block, builder.addConstant(block, 1));
    builder.addCall(block, set, {local});
    builder.addReturn(block, builder.addLoad(block, local));

    CHECK(verify(package).empty());
}

TEST_CASE("a borrowed unit cannot be consumed, returned, or forwarded to an owning parameter") {
    Cells s;
    auto builder = s.package.builder();
    auto take = s.take();

    auto forward =
        builder.createFunction("forward", {Parameter(s.unit_type, ParameterMode::BorrowMut)}, builder.voidType());
    auto forward_block = builder.createBlock(s.package.function(forward).root_region);
    builder.addCall(forward_block, take, {builder.addArgument(forward, forward_block, 0)});
    builder.addReturnVoid(forward_block);
    CHECK(hasDiagnostic(verify(s.package), diag::BorrowedValueConsumed));

    Cells returned;
    auto returned_builder = returned.package.builder();
    auto leak = returned_builder.createFunction("leak",
                                                {Parameter(returned.unit_type, ParameterMode::BorrowMut)},
                                                returned.unit_type);
    auto leak_block = returned_builder.createBlock(returned.package.function(leak).root_region);
    returned_builder.addReturn(leak_block, returned_builder.addArgument(leak, leak_block, 0));
    CHECK(hasDiagnostic(verify(returned.package), diag::BorrowEscapes));

    Cells published;
    auto published_builder = published.package.builder();
    auto publish = published_builder.createFunction("publish",
                                                    {Parameter(published.unit_type, ParameterMode::BorrowMut)},
                                                    published_builder.voidType());
    auto publish_block = published_builder.createBlock(published.package.function(publish).root_region);
    auto borrowed = published_builder.addArgument(publish, publish_block, 0);
    published_builder.addPublishField(publish_block,
                                      borrowed,
                                      published_builder.addUint64Constant(publish_block, 1),
                                      published.first);
    published_builder.addReturnVoid(publish_block);
    CHECK(hasDiagnostic(verify(published.package), diag::BorrowedValueConsumed));
}

TEST_CASE("a taken unit transfers ownership, so the caller cannot use it afterward") {
    Cells s;
    auto builder = s.package.builder();
    auto take = s.take();
    auto read = s.read();

    auto good = s.owner("good");
    auto good_block = builder.createBlock(s.package.function(good).root_region);
    auto good_cell = builder.addArgument(good, good_block, 0);
    builder.addCall(good_block, read, {good_cell});
    builder.addCall(good_block, take, {good_cell});
    builder.addReturnVoid(good_block);
    CHECK(verify(s.package).empty());

    auto reused = s.owner("reused");
    auto reused_block = builder.createBlock(s.package.function(reused).root_region);
    auto reused_cell = builder.addArgument(reused, reused_block, 0);
    builder.addCall(reused_block, take, {reused_cell});
    builder.addCall(reused_block, take, {reused_cell});
    builder.addReturnVoid(reused_block);
    CHECK(hasDiagnostic(verify(s.package), diag::ParserStateReused));
}

TEST_CASE("a taken vector is consumed by the call, like any other affine value") {
    Package package;
    auto builder = package.builder();
    auto vector = builder.vectorType(builder.int64Type());

    auto take = builder.createFunction("take", {Parameter(vector, ParameterMode::Take)}, builder.voidType());
    auto take_block = builder.createBlock(package.function(take).root_region);
    builder.addArgument(take, take_block, 0);
    builder.addReturnVoid(take_block);

    auto once = builder.createFunction("once", builder.voidType());
    auto once_block = builder.createBlock(package.function(once).root_region);
    builder.addCall(once_block, take, {builder.addVectorEmpty(once_block, builder.int64Type())});
    builder.addReturnVoid(once_block);
    CHECK(verify(package).empty());

    auto twice = builder.createFunction("twice", builder.voidType());
    auto twice_block = builder.createBlock(package.function(twice).root_region);
    auto both = builder.addVectorEmpty(twice_block, builder.int64Type());
    builder.addCall(twice_block, take, {both});
    builder.addCall(twice_block, take, {both});
    builder.addReturnVoid(twice_block);
    CHECK(hasDiagnostic(verify(package), diag::ParserStateReused));
}

TEST_CASE("a borrow reached after its owner was consumed is rejected") {
    Cells s;
    auto builder = s.package.builder();
    auto take = s.take();
    auto read = s.read();

    auto fn = s.owner();
    auto block = builder.createBlock(s.package.function(fn).root_region);
    auto cell = builder.addArgument(fn, block, 0);
    builder.addCall(block, take, {cell});
    builder.addCall(block, read, {cell});
    builder.addReturnVoid(block);

    CHECK(hasDiagnostic(verify(s.package), diag::UseAfterConsume));
}

TEST_CASE("a borrow after a consumption on some path is rejected, and one on another path is not") {
    Cells s;
    auto builder = s.package.builder();
    auto take = s.take();
    auto read = s.read();

    auto build = [&](bool borrow_on_other_path) {
        auto fn = builder.createFunction("branching",
                                         {Parameter(s.unit_type, ParameterMode::Take),
                                          Parameter(builder.boolType(), ParameterMode::Take)},
                                         builder.voidType());
        auto region = s.package.function(fn).root_region;
        auto entry = builder.createBlock(region);
        auto consume = builder.createBlock(region);
        auto other = builder.createBlock(region);
        auto join = builder.createBlock(region);
        auto cell = builder.addArgument(fn, entry, 0);
        auto flag = builder.addArgument(fn, entry, 1);
        builder.addBranch(entry, flag, consume, other);
        builder.addCall(consume, take, {cell});
        builder.addJump(consume, join);
        if ( borrow_on_other_path ) {
            builder.addCall(other, read, {cell});
            builder.addJump(other, join);
            builder.addReturnVoid(join);
        }
        else {
            builder.addJump(other, join);
            builder.addCall(join, read, {cell});
            builder.addReturnVoid(join);
        }
    };

    build(true);
    CHECK(verify(s.package).empty());
    build(false);
    CHECK(hasDiagnostic(verify(s.package), diag::UseAfterConsume));
}

TEST_CASE("a place derived from a unit cannot be used after the unit's ownership transfers") {
    Cells s;
    auto builder = s.package.builder();
    auto take = s.take();

    auto straight = s.owner("straight");
    auto block = builder.createBlock(s.package.function(straight).root_region);
    auto cell = builder.addArgument(straight, block, 0);
    auto place = builder.addFieldPlace(block, cell, s.first);
    builder.addLoad(block, place);
    builder.addCall(block, take, {cell});
    builder.addReturnVoid(block);
    CHECK(verify(s.package).empty());

    auto late = s.owner("late");
    auto late_block = builder.createBlock(s.package.function(late).root_region);
    auto late_cell = builder.addArgument(late, late_block, 0);
    auto late_place = builder.addFieldPlace(late_block, late_cell, s.first);
    builder.addCall(late_block, take, {late_cell});
    builder.addLoad(late_block, late_place);
    builder.addReturnVoid(late_block);
    auto diags = verify(s.package);
    CHECK(hasDiagnostic(diags, diag::UseAfterConsume));
}

TEST_CASE("a derived place is rejected after a consumption on some path, and accepted on another path") {
    Cells s;
    auto builder = s.package.builder();
    auto take = s.take();

    auto build = [&](bool access_on_other_path) {
        auto fn = builder.createFunction("branching",
                                         {Parameter(s.unit_type, ParameterMode::Take),
                                          Parameter(builder.boolType(), ParameterMode::Take)},
                                         builder.voidType());
        auto region = s.package.function(fn).root_region;
        auto entry = builder.createBlock(region);
        auto consume = builder.createBlock(region);
        auto other = builder.createBlock(region);
        auto join = builder.createBlock(region);
        auto cell = builder.addArgument(fn, entry, 0);
        auto flag = builder.addArgument(fn, entry, 1);
        auto place = builder.addFieldPlace(entry, cell, s.first);
        builder.addBranch(entry, flag, consume, other);
        builder.addCall(consume, take, {cell});
        builder.addJump(consume, join);
        if ( access_on_other_path ) {
            builder.addLoad(other, place);
            builder.addJump(other, join);
            builder.addReturnVoid(join);
        }
        else {
            builder.addJump(other, join);
            builder.addLoad(join, place);
            builder.addReturnVoid(join);
        }
    };

    build(true);
    CHECK(verify(s.package).empty());
    build(false);
    CHECK(hasDiagnostic(verify(s.package), diag::UseAfterConsume));
}

TEST_CASE("a place derived from a unit read out of storage ends with that unit's ownership") {
    Cells s;
    auto builder = s.package.builder();
    auto take = s.take();

    auto straight = s.owner("straight");
    auto block = builder.createBlock(s.package.function(straight).root_region);
    auto storage = builder.addLocalPlace(block, builder.addArgument(straight, block, 0));
    auto loaded = builder.addLoad(block, storage);
    auto place = builder.addFieldPlace(block, loaded, s.first);
    builder.addLoad(block, place);
    builder.addCall(block, take, {loaded});
    builder.addReturnVoid(block);
    CHECK(verify(s.package).empty());

    auto late = s.owner("late");
    auto late_block = builder.createBlock(s.package.function(late).root_region);
    auto late_storage = builder.addLocalPlace(late_block, builder.addArgument(late, late_block, 0));
    auto late_loaded = builder.addLoad(late_block, late_storage);
    auto late_place = builder.addFieldPlace(late_block, late_loaded, s.first);
    builder.addCall(late_block, take, {late_loaded});
    builder.addLoad(late_block, late_place);
    builder.addReturnVoid(late_block);
    CHECK(hasDiagnostic(verify(s.package), diag::UseAfterConsume));
}

TEST_CASE("a place derived from a loaded unit is rejected after a consumption on some path only") {
    Cells s;
    auto builder = s.package.builder();
    auto take = s.take();

    auto build = [&](bool access_on_other_path) {
        auto fn = builder.createFunction("branching",
                                         {Parameter(s.unit_type, ParameterMode::Take),
                                          Parameter(builder.boolType(), ParameterMode::Take)},
                                         builder.voidType());
        auto region = s.package.function(fn).root_region;
        auto entry = builder.createBlock(region);
        auto consume = builder.createBlock(region);
        auto other = builder.createBlock(region);
        auto join = builder.createBlock(region);
        auto owner = builder.addArgument(fn, entry, 0);
        auto flag = builder.addArgument(fn, entry, 1);
        auto storage = builder.addLocalPlace(entry, owner);
        auto loaded = builder.addLoad(entry, storage);
        auto place = builder.addFieldPlace(entry, loaded, s.first);
        builder.addBranch(entry, flag, consume, other);
        builder.addCall(consume, take, {loaded});
        builder.addJump(consume, join);
        if ( access_on_other_path ) {
            builder.addLoad(other, place);
            builder.addJump(other, join);
            builder.addReturnVoid(join);
        }
        else {
            builder.addJump(other, join);
            builder.addLoad(join, place);
            builder.addReturnVoid(join);
        }
    };

    build(true);
    CHECK(verify(s.package).empty());
    build(false);
    CHECK(hasDiagnostic(verify(s.package), diag::UseAfterConsume));
}

TEST_CASE("a borrowing call does not reset or bypass a unit's publication chain") {
    Cells s;
    auto builder = s.package.builder();
    auto read = s.read();
    auto state_type = builder.parserStateType();

    auto parser = builder.createParserFunction(s.unit, state_type, s.unit_type);
    auto block = builder.createBlock(s.package.function(parser).root_region);
    auto state = builder.addArgument(parser, block, 0);
    auto cell = builder.addUnitCreate(block, s.unit);
    auto first = builder.addReadInteger(block,
                                        state,
                                        ReadIntegerPayload{.width = 64,
                                                           .signedness = Signedness::Unsigned,
                                                           .byte_order = ByteOrder::Network});
    auto state1 = builder.addTupleGet(block, first, 0);
    auto cell1 = builder.addPublishField(block, cell, builder.addTupleGet(block, first, 1), s.first);
    builder.addCall(block, read, {cell1});
    auto second = builder.addReadInteger(block,
                                         state1,
                                         ReadIntegerPayload{.width = 64,
                                                            .signedness = Signedness::Unsigned,
                                                            .byte_order = ByteOrder::Network});
    auto state2 = builder.addTupleGet(block, second, 0);
    auto cell2 = builder.addPublishField(block, cell1, builder.addTupleGet(block, second, 1), s.second);
    builder.addCall(block, read, {cell2});
    builder.addParserFinish(block, state2, cell2);
    builder.addParserRoot(s.unit, parser);
    CHECK(verify(s.package).empty());

    // The borrow does not publish the missing field on the unit's behalf.
    Cells incomplete;
    auto incomplete_builder = incomplete.package.builder();
    auto incomplete_read = incomplete.read();
    auto incomplete_parser = incomplete_builder.createParserFunction(incomplete.unit,
                                                                     incomplete_builder.parserStateType(),
                                                                     incomplete.unit_type);
    auto incomplete_block = incomplete_builder.createBlock(incomplete.package.function(incomplete_parser).root_region);
    auto incomplete_state = incomplete_builder.addArgument(incomplete_parser, incomplete_block, 0);
    auto incomplete_cell = incomplete_builder.addUnitCreate(incomplete_block, incomplete.unit);
    incomplete_builder.addCall(incomplete_block, incomplete_read, {incomplete_cell});
    incomplete_builder.addParserFinish(incomplete_block, incomplete_state, incomplete_cell);
    CHECK(hasDiagnostic(verify(incomplete.package), diag::MissingFieldPublication));
}

TEST_CASE("a parameter's type must suit its mode") {
    Package package;
    auto builder = package.builder();
    auto place = builder.placeType(builder.int64Type());
    auto unit = builder.createUnitDecl("Cell");
    auto unit_type = builder.unitType(unit);

    auto check = [&](Parameter parameter) {
        auto fn = builder.createFunction("f", {parameter}, builder.voidType());
        auto block = builder.createBlock(package.function(fn).root_region);
        builder.addArgument(fn, block, 0);
        builder.addReturnVoid(block);
        return hasDiagnostic(verify(package), diag::NormalFunctionInvalidParameter);
    };

    // A borrow of storage or of an object, and a taken unit, vector, or set, suit their modes.
    CHECK_FALSE(check(Parameter(place, ParameterMode::Borrow)));
    CHECK_FALSE(check(Parameter(unit_type, ParameterMode::BorrowMut)));
    CHECK_FALSE(check(Parameter(builder.vectorType(builder.int64Type()), ParameterMode::Take)));
    CHECK_FALSE(check(Parameter(builder.setType(builder.int64Type()), ParameterMode::Take)));

    // A place is not a value that anything can own, and a borrow of a plain value has nothing to borrow.
    Package other;
    auto other_builder = other.builder();
    auto invalid = [&](Parameter parameter) {
        auto fn = other_builder.createFunction("f", {parameter}, other_builder.voidType());
        auto block = other_builder.createBlock(other.function(fn).root_region);
        other_builder.addArgument(fn, block, 0);
        other_builder.addReturnVoid(block);
        return hasDiagnostic(verify(other), diag::NormalFunctionInvalidParameter);
    };
    CHECK(invalid(Parameter(other_builder.placeType(other_builder.int64Type()), ParameterMode::Take)));
    CHECK(invalid(Parameter(other_builder.int64Type(), ParameterMode::Borrow)));
    CHECK(invalid(Parameter(other_builder.int64Type(), ParameterMode::BorrowMut)));
    CHECK(invalid(Parameter(other_builder.parserStateType(), ParameterMode::Borrow)));
    CHECK(invalid(Parameter(other_builder.parserStateType(), ParameterMode::Take)));
    CHECK(invalid(Parameter(other_builder.voidType(), ParameterMode::Take)));
}

TEST_CASE("a call must pass the type and count of each parameter") {
    Cells s;
    auto builder = s.package.builder();
    auto read = s.read();

    auto fn = builder.createFunction("caller", builder.voidType());
    auto block = builder.createBlock(s.package.function(fn).root_region);
    builder.addCall(block, read, {builder.addConstant(block, 1)});
    builder.addCall(block, read, {});
    builder.addReturnVoid(block);

    auto diags = verify(s.package);
    CHECK(hasDiagnostic(diags, diag::CallArgumentTypeMismatch));
    CHECK(hasDiagnostic(diags, diag::CallArgumentCountMismatch));
}

TEST_CASE("a call stays an ordered effect that reads and writes places") {
    auto effects = effectsFor(Opcode::Call);
    CHECK(effects.reads_places);
    CHECK(effects.writes_places);
    CHECK(effects.reads_world);
    CHECK(effects.writes_world);
    CHECK_EQ(schemaFor(Opcode::Call)->is_pure, false);
}

TEST_SUITE_END();
