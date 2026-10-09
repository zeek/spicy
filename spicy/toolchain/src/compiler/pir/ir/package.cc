// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <cassert>
#include <utility>

#include <spicy/compiler/detail/pir/ir/package.h>

namespace spicy::detail::pir::ir {

Package::Package() {
    _void_type = _types.add(Type{.kind = TypeKind::Void});
    _int64_type = _types.add(Type{.kind = TypeKind::Int64});
}

TypeId Package::uint8Type() {
    if ( ! _uint8_type.isSet() )
        _uint8_type = _types.add(Type{.kind = TypeKind::UInt8});
    return _uint8_type;
}

TypeId Package::uint64Type() {
    if ( ! _uint64_type.isSet() )
        _uint64_type = _types.add(Type{.kind = TypeKind::UInt64});
    return _uint64_type;
}

TypeId Package::bytesType() {
    if ( ! _bytes_type.isSet() )
        _bytes_type = _types.add(Type{.kind = TypeKind::Bytes});
    return _bytes_type;
}

TypeId Package::parserStateType() {
    if ( ! _parser_state_type.isSet() )
        _parser_state_type = _types.add(Type{.kind = TypeKind::ParserState});
    return _parser_state_type;
}

TypeId Package::unitType(TypeDeclId decl) {
    for ( size_t i = 0; i < _types.size(); ++i ) {
        auto id = TypeId{static_cast<uint32_t>(i)};
        const auto& t = _types.get(id);
        if ( t.kind == TypeKind::Unit && t.declaration == decl )
            return id;
    }

    return _types.add(Type{.kind = TypeKind::Unit, .declaration = decl});
}

TypeId Package::tupleType(std::vector<TypeId> elements) {
    for ( size_t i = 0; i < _types.size(); ++i ) {
        auto id = TypeId{static_cast<uint32_t>(i)};
        const auto& t = _types.get(id);
        if ( t.kind == TypeKind::Tuple && t.type_arguments == elements )
            return id;
    }

    return _types.add(Type{.kind = TypeKind::Tuple, .type_arguments = std::move(elements)});
}

TypeId Package::vectorType(TypeId element) {
    for ( size_t i = 0; i < _types.size(); ++i ) {
        auto id = TypeId{static_cast<uint32_t>(i)};
        const auto& t = _types.get(id);
        if ( t.kind == TypeKind::Vector && t.type_arguments == std::vector<TypeId>{element} )
            return id;
    }

    return _types.add(Type{.kind = TypeKind::Vector, .type_arguments = {element}});
}

TypeDeclId Package::createUnitDecl(std::string name, SourceSpanId span) {
    return _type_decls.add(TypeDecl{.kind = TypeDeclKind::Unit, .name = std::move(name), .span = span});
}

DeclId Package::createFieldDecl(TypeDeclId unit, std::string name, TypeId type, SourceSpanId span) {
    auto id = _declarations.add(Declaration{
        .kind = DeclKind::Field,
        .owner = unit,
        .name = std::move(name),
        .type = type,
        .span = span,
    });
    _type_decls.get(unit).fields.push_back(id);
    return id;
}

DeclId Package::createFieldDeclForTesting(TypeDeclId owner, std::string name, TypeId type, SourceSpanId span) {
    return _declarations.add(Declaration{
        .kind = DeclKind::Field,
        .owner = owner,
        .name = std::move(name),
        .type = type,
        .span = span,
    });
}

void Package::appendFieldForTesting(TypeDeclId owner, DeclId field) { _type_decls.get(owner).fields.push_back(field); }

void Package::addParserRoot(TypeDeclId unit, FunctionId function) {
    _parser_roots.push_back(ParserRoot{.unit = unit, .function = function});
}

FunctionId Package::createFunction(std::string name, TypeId result_type, SourceSpanId span) {
    auto root_region = createRegion();
    return _functions.add(Function{
        .name = std::move(name),
        .result_type = result_type,
        .root_region = root_region,
        .span = span,
    });
}

FunctionId Package::createParserFunction(TypeDeclId unit, TypeId state_type, TypeId unit_type, SourceSpanId span) {
    auto root_region = createRegion();
    return _functions.add(Function{
        .result_type = unit_type,
        .root_region = root_region,
        .kind = FunctionKind::Parser,
        .parameters = {state_type},
        .parser_unit = unit,
        .span = span,
    });
}

RegionId Package::createRegion() { return _regions.add(Region{}); }

BlockId Package::createBlock(RegionId region) {
    auto id = _blocks.add(Block{});
    _regions.get(region).blocks.push_back(id);
    return id;
}

InstId Package::addInst(BlockId block,
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

InstId Package::addInstForTesting(BlockId block,
                                  Opcode opcode,
                                  std::vector<InstId> args,
                                  TypeId result_type,
                                  InstPayload payload,
                                  SourceSpanId span) {
    auto id = _instructions.add(Inst{
        .opcode = opcode,
        .result_type = result_type,
        .args = std::move(args),
        .parent = block,
        .payload = payload,
        .regions = {},
        .span = span,
    });
    _blocks.get(block).insts.push_back(id);
    return id;
}

InstId Package::addConstant(BlockId block, int64_t value, SourceSpanId span) {
    return addInst(block, Opcode::Constant, {}, _int64_type, InstPayload(Int64Literal{value}), span);
}

InstId Package::addAdd(BlockId block, InstId lhs, InstId rhs, SourceSpanId span) {
    return addInst(block, Opcode::Add, {lhs, rhs}, _int64_type, {}, span);
}

InstId Package::addReturn(BlockId block, InstId value, SourceSpanId span) {
    return addInst(block, Opcode::Return, {value}, _void_type, {}, span);
}

InstId Package::addArgument(FunctionId function, BlockId block, uint32_t index, SourceSpanId span) {
    // result_type is invalid by default, remains if out-of-range. Validator
    // should report the error.
    TypeId result_type;
    if ( isValid(function) ) {
        const auto& fn = _functions.get(function);
        if ( index < fn.parameters.size() )
            result_type = fn.parameters[index];
    }

    return addInst(block, Opcode::Argument, {}, result_type, InstPayload(ArgumentPayload{index}), span);
}

InstId Package::addUnitCreate(BlockId block, TypeDeclId unit, SourceSpanId span) {
    return addInst(block, Opcode::UnitCreate, {}, unitType(unit), InstPayload(UnitPayload{unit}), span);
}

InstId Package::addReadInteger(BlockId block, InstId state, ReadIntegerPayload payload, SourceSpanId span) {
    auto result_type = tupleType({parserStateType(), payload.width == 64 ? uint64Type() : uint8Type()});
    return addInst(block, Opcode::ReadInteger, {state}, result_type, InstPayload(payload), span);
}

InstId Package::addTupleGet(BlockId block, InstId tuple_value, uint32_t index, SourceSpanId span) {
    TypeId result_type;
    if ( isValid(tuple_value) ) {
        const auto& tuple_type = type(inst(tuple_value).result_type);
        if ( index < tuple_type.type_arguments.size() )
            result_type = tuple_type.type_arguments[index];
    }

    return addInst(block, Opcode::TupleGet, {tuple_value}, result_type, InstPayload(TupleGetPayload{index}), span);
}

InstId Package::addPublishField(BlockId block, InstId unit_value, InstId value, DeclId field, SourceSpanId span) {
    TypeId result_type;
    if ( isValid(unit_value) )
        result_type = inst(unit_value).result_type;

    return addInst(block,
                   Opcode::PublishField,
                   {unit_value, value},
                   result_type,
                   InstPayload(FieldPayload{field}),
                   span);
}

InstId Package::addParserFinish(BlockId block, InstId state, InstId unit_value, SourceSpanId span) {
    return addInst(block, Opcode::Finish, {state, unit_value}, _void_type, {}, span);
}

InstId Package::addRegionArgument(BlockId block, uint32_t index, TypeId type, SourceSpanId span) {
    return addInst(block, Opcode::RegionArgument, {}, type, InstPayload(ArgumentPayload{index}), span);
}

InstId Package::addYield(BlockId block, std::vector<InstId> values, SourceSpanId span) {
    return addInst(block, Opcode::Yield, std::move(values), _void_type, {}, span);
}

InstId Package::addVectorEmpty(BlockId block, TypeId element, SourceSpanId span) {
    return addInst(block, Opcode::VectorEmpty, {}, vectorType(element), {}, span);
}

InstId Package::addVectorAppend(BlockId block, InstId vector, InstId value, SourceSpanId span) {
    return addInst(block, Opcode::VectorAppend, {vector, value}, inst(vector).result_type, {}, span);
}

InstId Package::addEnterBound(BlockId block, InstId state, InstId length, SourceSpanId span) {
    return addInst(block, Opcode::EnterBound, {state, length}, parserStateType(), {}, span);
}

InstId Package::addLeaveBound(BlockId block, InstId state, SourceSpanId span) {
    return addInst(block, Opcode::LeaveBound, {state}, parserStateType(), {}, span);
}

InstId Package::addRepeatToBound(BlockId block, std::vector<InstId> carried, RegionId body, SourceSpanId span) {
    std::vector<TypeId> result_types;
    result_types.reserve(carried.size());
    for ( auto value : carried )
        result_types.push_back(inst(value).result_type);

    auto id = addInst(block, Opcode::RepeatToBound, std::move(carried), tupleType(std::move(result_types)), {}, span);
    _instructions.get(id).regions.push_back(body);
    return id;
}

InstId Package::addParseSubunit(BlockId block, InstId state, FunctionId child, SourceSpanId span) {
    return addInst(block,
                   Opcode::ParseSubunit,
                   {state},
                   tupleType({parserStateType(), function(child).result_type}),
                   InstPayload(FunctionPayload{child}),
                   span);
}

InstId Package::addReadBytes(BlockId block, InstId state, uint64_t length, SourceSpanId span) {
    return addInst(block,
                   Opcode::ReadBytes,
                   {state},
                   tupleType({parserStateType(), bytesType()}),
                   InstPayload(ReadBytesPayload{length}),
                   span);
}

// Useful for optimization
void Package::replaceInst(InstId id, Opcode opcode, std::vector<InstId> args, InstPayload payload) {
    auto& inst = _instructions.get(id);
    inst.opcode = opcode;
    inst.args = std::move(args);
    inst.payload = payload;
}

} // namespace spicy::detail::pir::ir
