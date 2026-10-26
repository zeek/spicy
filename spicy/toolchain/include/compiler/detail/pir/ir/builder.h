// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <spicy/compiler/detail/pir/ir/id.h>
#include <spicy/compiler/detail/pir/ir/package.h>
#include <spicy/compiler/detail/pir/ir/source.h>

namespace spicy::detail::pir::ir {

class Builder {
public:
    explicit Builder(Package& package) : _package(package) {}

    TypeId voidType() const noexcept { return _package._void_type; }
    TypeId int64Type() const noexcept { return _package._int64_type; }

    /** Interns `uint8` lazily so procedural-only packages keep stable type numbering. */
    TypeId uint8Type();
    TypeId uint64Type();
    TypeId bytesType();
    /** Interns `parser.state` lazily so procedural-only packages keep stable type numbering. */
    TypeId parserStateType();

    /** Interns a nominal unit type structurally by `TypeDeclId`. */
    TypeId unitType(TypeDeclId decl);
    /** Interns an opaque value type nominally by `TypeDeclId`. */
    TypeId opaqueType(TypeDeclId decl);
    /** Interns a tuple type structurally by its element types. */
    TypeId tupleType(std::vector<TypeId> elements);
    TypeId vectorType(TypeId element);
    /** Interns a writable place holding `element`; places are never stored in other values. */
    TypeId placeType(TypeId element);

    /** Declares a nominal unit type; returns its identity. */
    TypeDeclId createUnitDecl(std::string name, SourceSpanId span = {});
    /** Declares a field owned by `unit`, appended in call order. */
    DeclId createFieldDecl(TypeDeclId unit, std::string name, TypeId type, SourceSpanId span = {});
    /** Declares a nominal opaque value type bound to the native type described by `info`. */
    TypeDeclId createOpaqueTypeDecl(std::string name, OpaqueTypeInfo info, SourceSpanId span = {});
    /** Declares a function implemented outside PIR and returns its identity. */
    ForeignFunctionId createForeignFunction(std::string name,
                                            std::string cxx_name,
                                            std::vector<TypeId> parameters,
                                            TypeId result_type,
                                            SourceSpanId span = {});

    /** Adds unchecked declaration content for verifier tests: does not append to `owner`'s fields. */
    DeclId createFieldDeclForTesting(TypeDeclId owner, std::string name, TypeId type, SourceSpanId span = {});
    /** Appends `field` to `owner`'s fields list again, for verifier tests of duplicate membership. */
    void appendFieldForTesting(TypeDeclId owner, DeclId field);

    /** Appends a selected parser implementation; call only once the function is complete. */
    void addParserRoot(TypeDeclId unit, FunctionId function);
    /** Appends a selected public ordinary function; call only once the function is complete. */
    void addFunctionRoot(FunctionId function);

    FunctionId createFunction(std::string name, TypeId result_type, SourceSpanId span = {});
    /** Creates an ordinary function whose parameters are `parameters`, in order. */
    FunctionId createFunction(std::string name,
                              std::vector<TypeId> parameters,
                              TypeId result_type,
                              SourceSpanId span = {});
    /** Creates a `FunctionKind::Parser` function whose one parameter is `state_type`. */
    FunctionId createParserFunction(TypeDeclId unit, TypeId state_type, TypeId unit_type, SourceSpanId span = {});
    RegionId createRegion();
    BlockId createBlock(RegionId region);

    InstId addInst(BlockId block,
                   Opcode opcode,
                   std::vector<InstId> args,
                   TypeId result_type,
                   InstPayload payload = {},
                   SourceSpanId span = {});

    /** Adds unchecked IR for verifier tests. */
    InstId addInstForTesting(BlockId block,
                             Opcode opcode,
                             std::vector<InstId> args,
                             TypeId result_type,
                             InstPayload payload = {},
                             SourceSpanId span = {});

    InstId addConstant(BlockId block, int64_t value, SourceSpanId span = {});
    InstId addAdd(BlockId block, InstId lhs, InstId rhs, SourceSpanId span = {});
    InstId addReturn(BlockId block, InstId value, SourceSpanId span = {});
    /** Adds the `core.return` of a function with a `void` result, which carries no operand. */
    InstId addReturnVoid(BlockId block, SourceSpanId span = {});

    /**
     * Adds `core.argument` for parameter `index` of `function`; must be added in increasing
     * order, block-leading. The caller supplies `function` directly rather than this construction
     * helper rediscovering it by scanning every function for one whose region contains `block`.
     */
    InstId addArgument(FunctionId function, BlockId block, uint32_t index, SourceSpanId span = {});
    /** Adds `unit.create` for `unit`. */
    InstId addUnitCreate(BlockId block, TypeDeclId unit, SourceSpanId span = {});
    /** Adds `parser.read_integer` over `state`. */
    InstId addReadInteger(BlockId block, InstId state, ReadIntegerPayload payload, SourceSpanId span = {});
    /** Adds `core.tuple_get` selecting element `index` of `tuple_value`. */
    InstId addTupleGet(BlockId block, InstId tuple_value, uint32_t index, SourceSpanId span = {});
    /** Adds `unit.publish_field` writing `value` into `field` of `unit_value`. */
    InstId addPublishField(BlockId block, InstId unit_value, InstId value, DeclId field, SourceSpanId span = {});
    /** Adds the terminating `parser.finish` over `state` and `unit_value`. */
    InstId addParserFinish(BlockId block, InstId state, InstId unit_value, SourceSpanId span = {});
    InstId addRegionArgument(BlockId block, uint32_t index, TypeId type, SourceSpanId span = {});
    InstId addYield(BlockId block, std::vector<InstId> values, SourceSpanId span = {});
    InstId addVectorEmpty(BlockId block, TypeId element, SourceSpanId span = {});
    InstId addVectorAppend(BlockId block, InstId vector, InstId value, SourceSpanId span = {});
    InstId addEnterBound(BlockId block, InstId state, InstId length, SourceSpanId span = {});
    InstId addLeaveBound(BlockId block, InstId state, SourceSpanId span = {});
    InstId addRepeatToBound(BlockId block, std::vector<InstId> carried, RegionId body, SourceSpanId span = {});
    InstId addParseSubunit(BlockId block, InstId state, FunctionId child, SourceSpanId span = {});
    InstId addReadBytes(BlockId block, InstId state, uint64_t length, SourceSpanId span = {});
    /** Adds `opaque.op` calling `function` with `args`; its result type is the declaration's. */
    InstId addOpaqueOp(BlockId block, ForeignFunctionId function, std::vector<InstId> args, SourceSpanId span = {});
    /** Adds `core.call` calling `function` with `args`; its result type is the function's. */
    InstId addCall(BlockId block, FunctionId function, std::vector<InstId> args, SourceSpanId span = {});
    /** Adds `core.local_place` that holds a copy of `initial`, and returns the place. */
    InstId addLocalPlace(BlockId block, InstId initial, SourceSpanId span = {});
    /** Adds `core.load` reading the element stored in `place`. */
    InstId addLoad(BlockId block, InstId place, SourceSpanId span = {});
    /** Adds `core.store` writing `value` into `place`. */
    InstId addStore(BlockId block, InstId place, InstId value, SourceSpanId span = {});

private:
    Package& _package;
};

} // namespace spicy::detail::pir::ir
