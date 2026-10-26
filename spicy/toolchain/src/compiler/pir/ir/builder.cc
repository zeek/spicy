// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <cassert>
#include <utility>

#include <spicy/compiler/detail/pir/ir/builder.h>

namespace spicy::detail::pir::ir {

TypeId Builder::uint8Type() {
    if ( ! _package._uint8_type.isSet() )
        _package._uint8_type = _package._types.add(Type{.kind = TypeKind::UInt8});
    return _package._uint8_type;
}

TypeId Builder::uint64Type() {
    if ( ! _package._uint64_type.isSet() )
        _package._uint64_type = _package._types.add(Type{.kind = TypeKind::UInt64});
    return _package._uint64_type;
}

TypeId Builder::bytesType() {
    if ( ! _package._bytes_type.isSet() )
        _package._bytes_type = _package._types.add(Type{.kind = TypeKind::Bytes});
    return _package._bytes_type;
}

TypeId Builder::parserStateType() {
    if ( ! _package._parser_state_type.isSet() )
        _package._parser_state_type = _package._types.add(Type{.kind = TypeKind::ParserState});
    return _package._parser_state_type;
}

TypeId Builder::unitType(TypeDeclId decl) {
    for ( size_t i = 0; i < _package._types.size(); ++i ) {
        auto id = TypeId{static_cast<uint32_t>(i)};
        const auto& t = _package._types.get(id);
        if ( t.kind == TypeKind::Unit && t.declaration == decl )
            return id;
    }

    return _package._types.add(Type{.kind = TypeKind::Unit, .declaration = decl});
}

TypeId Builder::opaqueType(TypeDeclId decl) {
    for ( size_t i = 0; i < _package._types.size(); ++i ) {
        auto id = TypeId{static_cast<uint32_t>(i)};
        const auto& t = _package._types.get(id);
        if ( t.kind == TypeKind::Opaque && t.declaration == decl )
            return id;
    }

    return _package._types.add(Type{.kind = TypeKind::Opaque, .declaration = decl});
}

TypeId Builder::tupleType(std::vector<TypeId> elements) {
    for ( size_t i = 0; i < _package._types.size(); ++i ) {
        auto id = TypeId{static_cast<uint32_t>(i)};
        const auto& t = _package._types.get(id);
        if ( t.kind == TypeKind::Tuple && t.type_arguments == elements )
            return id;
    }

    return _package._types.add(Type{.kind = TypeKind::Tuple, .type_arguments = std::move(elements)});
}

TypeId Builder::vectorType(TypeId element) {
    for ( size_t i = 0; i < _package._types.size(); ++i ) {
        auto id = TypeId{static_cast<uint32_t>(i)};
        const auto& t = _package._types.get(id);
        if ( t.kind == TypeKind::Vector && t.type_arguments == std::vector<TypeId>{element} )
            return id;
    }

    return _package._types.add(Type{.kind = TypeKind::Vector, .type_arguments = {element}});
}

TypeDeclId Builder::createUnitDecl(std::string name, SourceSpanId span) {
    return _package._type_decls.add(TypeDecl{.kind = TypeDeclKind::Unit, .name = std::move(name), .span = span});
}

DeclId Builder::createFieldDecl(TypeDeclId unit, std::string name, TypeId type, SourceSpanId span) {
    auto id = _package._declarations.add(Declaration{
        .kind = DeclKind::Field,
        .owner = unit,
        .name = std::move(name),
        .type = type,
        .span = span,
    });
    _package._type_decls.get(unit).fields.push_back(id);
    return id;
}

DeclId Builder::createFieldDeclForTesting(TypeDeclId owner, std::string name, TypeId type, SourceSpanId span) {
    return _package._declarations.add(Declaration{
        .kind = DeclKind::Field,
        .owner = owner,
        .name = std::move(name),
        .type = type,
        .span = span,
    });
}

void Builder::appendFieldForTesting(TypeDeclId owner, DeclId field) {
    _package._type_decls.get(owner).fields.push_back(field);
}

TypeDeclId Builder::createOpaqueTypeDecl(std::string name, OpaqueTypeInfo info, SourceSpanId span) {
    return _package._type_decls.add(
        TypeDecl{.kind = TypeDeclKind::Opaque, .name = std::move(name), .opaque = std::move(info), .span = span});
}

ForeignFunctionId Builder::createForeignFunction(std::string name,
                                                 std::string cxx_name,
                                                 std::vector<TypeId> parameters,
                                                 TypeId result_type,
                                                 SourceSpanId span) {
    return _package._foreign_functions.add(ForeignFunction{
        .name = std::move(name),
        .cxx_name = std::move(cxx_name),
        .parameters = std::move(parameters),
        .result_type = result_type,
        .span = span,
    });
}

void Builder::addParserRoot(TypeDeclId unit, FunctionId function) {
    _package._parser_roots.push_back(ParserRoot{.unit = unit, .function = function});
}

FunctionId Builder::createFunction(std::string name, TypeId result_type, SourceSpanId span) {
    auto root_region = createRegion();
    return _package._functions.add(Function{
        .name = std::move(name),
        .result_type = result_type,
        .root_region = root_region,
        .span = span,
    });
}

FunctionId Builder::createParserFunction(TypeDeclId unit, TypeId state_type, TypeId unit_type, SourceSpanId span) {
    auto root_region = createRegion();
    return _package._functions.add(Function{
        .result_type = unit_type,
        .root_region = root_region,
        .kind = FunctionKind::Parser,
        .parameters = {state_type},
        .parser_unit = unit,
        .span = span,
    });
}

RegionId Builder::createRegion() { return _package._regions.add(Region{}); }

BlockId Builder::createBlock(RegionId region) {
    auto id = _package._blocks.add(Block{});
    _package._regions.get(region).blocks.push_back(id);
    return id;
}

InstId Builder::addInst(BlockId block,
                        Opcode opcode,
                        std::vector<InstId> args,
                        TypeId result_type,
                        InstPayload payload,
                        SourceSpanId span) {
    [[maybe_unused]] const auto* schema = schemaFor(opcode);
    assert(schema && "addInst() requires a recognized opcode; use addInstForTesting() for deliberately malformed IR");
    assert(schema->variadic ? args.size() >= schema->operandCount() : args.size() == schema->operandCount());
    assert(payloadMatchesKind(payload, schema->payload_kind));

    return addInstForTesting(block, opcode, std::move(args), result_type, payload, span);
}

InstId Builder::addInstForTesting(BlockId block,
                                  Opcode opcode,
                                  std::vector<InstId> args,
                                  TypeId result_type,
                                  InstPayload payload,
                                  SourceSpanId span) {
    auto id = _package._instructions.add(Inst{
        .opcode = opcode,
        .result_type = result_type,
        .args = std::move(args),
        .parent = block,
        .payload = payload,
        .regions = {},
        .span = span,
    });
    _package._blocks.get(block).insts.push_back(id);
    return id;
}

InstId Builder::addConstant(BlockId block, int64_t value, SourceSpanId span) {
    return addInst(block, Opcode::Constant, {}, _package._int64_type, InstPayload(Int64Literal{value}), span);
}

InstId Builder::addAdd(BlockId block, InstId lhs, InstId rhs, SourceSpanId span) {
    return addInst(block, Opcode::Add, {lhs, rhs}, _package._int64_type, {}, span);
}

InstId Builder::addReturn(BlockId block, InstId value, SourceSpanId span) {
    return addInst(block, Opcode::Return, {value}, _package._void_type, {}, span);
}

InstId Builder::addArgument(FunctionId function, BlockId block, uint32_t index, SourceSpanId span) {
    // result_type is invalid by default, remains if out-of-range. Validator
    // should report the error.
    TypeId result_type;
    if ( _package.isValid(function) ) {
        const auto& fn = _package._functions.get(function);
        if ( index < fn.parameters.size() )
            result_type = fn.parameters[index];
    }

    return addInst(block, Opcode::Argument, {}, result_type, InstPayload(ArgumentPayload{index}), span);
}

InstId Builder::addUnitCreate(BlockId block, TypeDeclId unit, SourceSpanId span) {
    return addInst(block, Opcode::UnitCreate, {}, unitType(unit), InstPayload(UnitPayload{unit}), span);
}

InstId Builder::addReadInteger(BlockId block, InstId state, ReadIntegerPayload payload, SourceSpanId span) {
    auto result_type = tupleType({parserStateType(), payload.width == 64 ? uint64Type() : uint8Type()});
    return addInst(block, Opcode::ReadInteger, {state}, result_type, InstPayload(payload), span);
}

InstId Builder::addTupleGet(BlockId block, InstId tuple_value, uint32_t index, SourceSpanId span) {
    TypeId result_type;
    if ( _package.isValid(tuple_value) ) {
        const auto& tuple_type = _package.type(_package.inst(tuple_value).result_type);
        if ( index < tuple_type.type_arguments.size() )
            result_type = tuple_type.type_arguments[index];
    }

    return addInst(block, Opcode::TupleGet, {tuple_value}, result_type, InstPayload(TupleGetPayload{index}), span);
}

InstId Builder::addPublishField(BlockId block, InstId unit_value, InstId value, DeclId field, SourceSpanId span) {
    TypeId result_type;
    if ( _package.isValid(unit_value) )
        result_type = _package.inst(unit_value).result_type;

    return addInst(block,
                   Opcode::PublishField,
                   {unit_value, value},
                   result_type,
                   InstPayload(FieldPayload{field}),
                   span);
}

InstId Builder::addParserFinish(BlockId block, InstId state, InstId unit_value, SourceSpanId span) {
    return addInst(block, Opcode::Finish, {state, unit_value}, _package._void_type, {}, span);
}

InstId Builder::addRegionArgument(BlockId block, uint32_t index, TypeId type, SourceSpanId span) {
    return addInst(block, Opcode::RegionArgument, {}, type, InstPayload(ArgumentPayload{index}), span);
}

InstId Builder::addYield(BlockId block, std::vector<InstId> values, SourceSpanId span) {
    return addInst(block, Opcode::Yield, std::move(values), _package._void_type, {}, span);
}

InstId Builder::addVectorEmpty(BlockId block, TypeId element, SourceSpanId span) {
    return addInst(block, Opcode::VectorEmpty, {}, vectorType(element), {}, span);
}

InstId Builder::addVectorAppend(BlockId block, InstId vector, InstId value, SourceSpanId span) {
    return addInst(block, Opcode::VectorAppend, {vector, value}, _package.inst(vector).result_type, {}, span);
}

InstId Builder::addEnterBound(BlockId block, InstId state, InstId length, SourceSpanId span) {
    return addInst(block, Opcode::EnterBound, {state, length}, parserStateType(), {}, span);
}

InstId Builder::addLeaveBound(BlockId block, InstId state, SourceSpanId span) {
    return addInst(block, Opcode::LeaveBound, {state}, parserStateType(), {}, span);
}

InstId Builder::addRepeatToBound(BlockId block, std::vector<InstId> carried, RegionId body, SourceSpanId span) {
    std::vector<TypeId> result_types;
    result_types.reserve(carried.size());
    for ( auto value : carried )
        result_types.push_back(_package.inst(value).result_type);

    auto id = addInst(block, Opcode::RepeatToBound, std::move(carried), tupleType(std::move(result_types)), {}, span);
    _package._instructions.get(id).regions.push_back(body);
    return id;
}

InstId Builder::addParseSubunit(BlockId block, InstId state, FunctionId child, SourceSpanId span) {
    return addInst(block,
                   Opcode::ParseSubunit,
                   {state},
                   tupleType({parserStateType(), _package.function(child).result_type}),
                   InstPayload(FunctionPayload{child}),
                   span);
}

InstId Builder::addOpaqueOp(BlockId block, ForeignFunctionId function, std::vector<InstId> args, SourceSpanId span) {
    // An invalid function leaves the result type invalid; the verifier reports the bad payload.
    TypeId result_type;
    if ( _package.isValid(function) )
        result_type = _package.foreignFunction(function).result_type;

    return addInst(block,
                   Opcode::OpaqueOp,
                   std::move(args),
                   result_type,
                   InstPayload(ForeignFunctionPayload{function}),
                   span);
}

InstId Builder::addReadBytes(BlockId block, InstId state, uint64_t length, SourceSpanId span) {
    return addInst(block,
                   Opcode::ReadBytes,
                   {state},
                   tupleType({parserStateType(), bytesType()}),
                   InstPayload(ReadBytesPayload{length}),
                   span);
}

} // namespace spicy::detail::pir::ir
