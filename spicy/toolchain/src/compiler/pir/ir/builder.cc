// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <algorithm>
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

TypeId Builder::boolType() {
    if ( ! _package._bool_type.isSet() )
        _package._bool_type = _package._types.add(Type{.kind = TypeKind::Bool});
    return _package._bool_type;
}

TypeId Builder::stringType() {
    if ( ! _package._string_type.isSet() )
        _package._string_type = _package._types.add(Type{.kind = TypeKind::String});
    return _package._string_type;
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

TypeId Builder::placeType(TypeId element) {
    for ( size_t i = 0; i < _package._types.size(); ++i ) {
        auto id = TypeId{static_cast<uint32_t>(i)};
        const auto& t = _package._types.get(id);
        if ( t.kind == TypeKind::Place && t.type_arguments == std::vector<TypeId>{element} )
            return id;
    }

    return _package._types.add(Type{.kind = TypeKind::Place, .type_arguments = {element}});
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
                                                 std::vector<ForeignParameter> parameters,
                                                 TypeId result_type,
                                                 SourceSpanId span,
                                                 bool have_prototype) {
    return _package._foreign_functions.add(ForeignFunction{
        .name = std::move(name),
        .cxx_name = std::move(cxx_name),
        .parameters = std::move(parameters),
        .result_type = result_type,
        .have_prototype = have_prototype,
        .span = span,
    });
}

void Builder::addParserRoot(TypeDeclId unit, FunctionId function) {
    _package._parser_roots.push_back(ParserRoot{.unit = unit, .function = function});
}

void Builder::addFunctionRoot(FunctionId function) { _package._function_roots.push_back(function); }

GlobalId Builder::createGlobal(std::string name, TypeId type, SourceSpanId span) {
    return _package._globals.add(Global{
        .name = std::move(name),
        .type = type,
        .initializer = {},
        .span = span,
    });
}

void Builder::setGlobalInitializer(GlobalId global, FunctionId initializer) {
    _package._globals.get(global).initializer = initializer;
}

void Builder::addInitializer(InitPhase phase, FunctionId function) {
    _package._initializers.push_back(Initializer{.phase = phase, .function = function});
}

void Builder::addCxxInclude(std::string header) {
    auto& includes = _package._cxx_includes;
    if ( std::ranges::find(includes, header) == includes.end() )
        includes.push_back(std::move(header));
}

FunctionId Builder::createFunction(std::string name, TypeId result_type, SourceSpanId span) {
    return createFunction(std::move(name), {}, result_type, span);
}

FunctionId Builder::createHookFunction(std::string name, TypeId unit, SourceSpanId span) {
    return _package._functions.add(Function{
        .name = std::move(name),
        .result_type = _package._void_type,
        .root_region = createRegion(),
        .kind = FunctionKind::Hook,
        .parameters = {unit},
        .span = span,
    });
}

FunctionId Builder::createFunction(std::string name,
                                   std::vector<TypeId> parameters,
                                   TypeId result_type,
                                   SourceSpanId span) {
    auto root_region = createRegion();
    return _package._functions.add(Function{
        .name = std::move(name),
        .result_type = result_type,
        .root_region = root_region,
        .parameters = std::move(parameters),
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
    // A void return is the only opcode whose operand count may be zero beyond its variadic form.
    assert(schema->variadic ? args.size() >= schema->operandCount() :
                              args.size() == schema->operandCount() || (opcode == Opcode::Return && args.empty()));
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

InstId Builder::addReturnVoid(BlockId block, SourceSpanId span) {
    return addInst(block, Opcode::Return, {}, _package._void_type, {}, span);
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

InstId Builder::addCall(BlockId block, FunctionId function, std::vector<InstId> args, SourceSpanId span) {
    // An invalid function leaves the result type invalid; the verifier reports the bad payload.
    TypeId result_type;
    if ( _package.isValid(function) )
        result_type = _package.function(function).result_type;

    return addInst(block, Opcode::Call, std::move(args), result_type, InstPayload(FunctionPayload{function}), span);
}

InstId Builder::addTuple(BlockId block, std::vector<InstId> elements, SourceSpanId span) {
    std::vector<TypeId> types;
    types.reserve(elements.size());
    for ( auto element : elements )
        types.push_back(_package.inst(element).result_type);

    return addInst(block, Opcode::Tuple, std::move(elements), tupleType(std::move(types)), {}, span);
}

InstId Builder::addBoolConstant(BlockId block, bool value, SourceSpanId span) {
    return addInst(block, Opcode::BoolConstant, {}, boolType(), InstPayload(BoolLiteral{value}), span);
}

InstId Builder::addStringConstant(BlockId block, std::string value, SourceSpanId span) {
    return addInst(block, Opcode::StringConstant, {}, stringType(), InstPayload(StringLiteral{std::move(value)}), span);
}

InstId Builder::addBytesConstant(BlockId block, std::string value, SourceSpanId span) {
    return addInst(block, Opcode::BytesConstant, {}, bytesType(), InstPayload(BytesLiteral{std::move(value)}), span);
}

InstId Builder::addLocalPlace(BlockId block, InstId initial, SourceSpanId span) {
    TypeId result_type;
    if ( _package.isValid(initial) )
        result_type = placeType(_package.inst(initial).result_type);

    return addInst(block, Opcode::LocalPlace, {initial}, result_type, {}, span);
}

InstId Builder::addFieldPlace(BlockId block, InstId unit_value, DeclId field, SourceSpanId span) {
    TypeId result_type;
    if ( _package.isValid(field) )
        result_type = placeType(_package.declaration(field).type);

    return addInst(block, Opcode::FieldPlace, {unit_value}, result_type, InstPayload(FieldPayload{field}), span);
}

InstId Builder::addGlobalPlace(BlockId block, GlobalId global, SourceSpanId span) {
    TypeId result_type;
    if ( _package.isValid(global) )
        result_type = placeType(_package.global(global).type);

    return addInst(block, Opcode::GlobalPlace, {}, result_type, InstPayload(GlobalPayload{global}), span);
}

InstId Builder::addInvokeHook(BlockId block, InstId unit_value, FunctionId hook, SourceSpanId span) {
    return addInst(block,
                   Opcode::InvokeHook,
                   {unit_value},
                   _package._void_type,
                   InstPayload(FunctionPayload{hook}),
                   span);
}

InstId Builder::addLoad(BlockId block, InstId place, SourceSpanId span) {
    TypeId result_type;
    if ( _package.isValid(place) ) {
        const auto& place_type = _package.type(_package.inst(place).result_type);
        if ( place_type.kind == TypeKind::Place && place_type.type_arguments.size() == 1 )
            result_type = place_type.type_arguments[0];
    }

    return addInst(block, Opcode::Load, {place}, result_type, {}, span);
}

InstId Builder::addStore(BlockId block, InstId place, InstId value, SourceSpanId span) {
    return addInst(block, Opcode::Store, {place, value}, _package._void_type, {}, span);
}

InstId Builder::addEqual(BlockId block, InstId lhs, InstId rhs, SourceSpanId span) {
    return addInst(block, Opcode::Equal, {lhs, rhs}, boolType(), {}, span);
}

InstId Builder::addBranch(BlockId block, InstId condition, BlockId then_block, BlockId else_block, SourceSpanId span) {
    return addInst(block,
                   Opcode::Branch,
                   {condition},
                   _package._void_type,
                   BranchPayload{.then_block = then_block, .else_block = else_block},
                   span);
}

InstId Builder::addJump(BlockId block, BlockId target, SourceSpanId span) {
    return addInst(block, Opcode::Jump, {}, _package._void_type, JumpPayload{.target = target}, span);
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
