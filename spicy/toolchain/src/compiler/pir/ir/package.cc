// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <algorithm>
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
    [[maybe_unused]] auto schema = lookupSchema(opcode);
    assert(schema && "addInst() requires a recognized opcode; use addInstForTesting() for deliberately malformed IR");
    assert(args.size() == schema->operand_count);
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

InstId Package::addArgument(BlockId block, uint32_t index, SourceSpanId span) {
    // `core.argument`'s result is the owning function's indexed parameter type. Find that
    // function by which one's root region contains `block`; the verifier is responsible for
    // diagnosing a block that (malformed-IR-test-only) belongs to no function or an out-of-range
    // index, so a missing match here just falls through to an invalid `TypeId`.
    TypeId result_type;
    for ( size_t i = 0; i < _functions.size() && ! result_type.isSet(); ++i ) {
        const auto& fn = _functions.get(FunctionId{static_cast<uint32_t>(i)});
        if ( ! isValid(fn.root_region) )
            continue;

        const auto& blocks = region(fn.root_region).blocks;
        if ( std::find(blocks.begin(), blocks.end(), block) == blocks.end() )
            continue;

        if ( index < fn.parameters.size() )
            result_type = fn.parameters[index];
    }

    return addInst(block, Opcode::Argument, {}, result_type, InstPayload(ArgumentPayload{index}), span);
}

InstId Package::addUnitCreate(BlockId block, TypeDeclId unit, SourceSpanId span) {
    return addInst(block, Opcode::UnitCreate, {}, unitType(unit), InstPayload(UnitPayload{unit}), span);
}

InstId Package::addReadInteger(BlockId block, InstId state, ReadIntegerPayload payload, SourceSpanId span) {
    auto result_type = tupleType({parserStateType(), uint8Type()});
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

void Package::replaceInst(InstId id, Opcode opcode, std::vector<InstId> args, InstPayload payload) {
    auto& inst = _instructions.get(id);
    inst.opcode = opcode;
    inst.args = std::move(args);
    inst.payload = payload;
}

} // namespace spicy::detail::pir::ir
