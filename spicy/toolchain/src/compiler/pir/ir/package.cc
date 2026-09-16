// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <cassert>
#include <utility>

#include <spicy/compiler/detail/pir/ir/package.h>

namespace spicy::detail::pir::ir {

Package::Package() {
    _void_type = _types.add(Type{.kind = TypeKind::Void});
    _int64_type = _types.add(Type{.kind = TypeKind::Int64});
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
    assert(std::holds_alternative<std::monostate>(payload) == (schema->payload_kind == PayloadKind::None));

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
    return addInst(block, Opcode::Constant, {}, _int64_type, InstPayload(value), span);
}

InstId Package::addAdd(BlockId block, InstId lhs, InstId rhs, SourceSpanId span) {
    return addInst(block, Opcode::Add, {lhs, rhs}, _int64_type, {}, span);
}

InstId Package::addReturn(BlockId block, InstId value, SourceSpanId span) {
    return addInst(block, Opcode::Return, {value}, _void_type, {}, span);
}

void Package::replaceInst(InstId id, Opcode opcode, std::vector<InstId> args, InstPayload payload) {
    auto& inst = _instructions.get(id);
    inst.opcode = opcode;
    inst.args = std::move(args);
    inst.payload = payload;
}

} // namespace spicy::detail::pir::ir
