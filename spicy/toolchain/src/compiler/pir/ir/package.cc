// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <algorithm>
#include <unordered_set>
#include <utility>

#include <spicy/compiler/detail/pir/ir/builder.h>
#include <spicy/compiler/detail/pir/ir/package.h>

namespace spicy::detail::pir::ir {

Package::Package() {
    _void_type = _types.add(Type{.kind = TypeKind::Void});
    _int64_type =
        _types.add(Type{.kind = TypeKind::Integer, .integer = {.width = 64, .signedness = Signedness::Signed}});
}

Builder Package::builder() { return Builder(*this); }

// Useful for optimization
void Package::replaceInst(InstId id, Opcode opcode, std::vector<InstId> args, InstPayload payload) {
    auto& inst = _instructions.get(id);
    inst.opcode = opcode;
    inst.args = std::move(args);
    inst.payload = payload;
}

namespace {

ValueDiscipline typeDiscipline(const Package& package, TypeId id, std::unordered_set<uint32_t>& visiting) {
    if ( ! package.isValid(id) )
        return ValueDiscipline::Copyable;

    if ( ! visiting.insert(id.index).second )
        return ValueDiscipline::Copyable;

    const auto& type = package.type(id);
    if ( typeKindDiscipline(type.kind) == ValueDiscipline::Affine )
        return ValueDiscipline::Affine;

    if ( type.kind == TypeKind::Tuple )
        for ( auto element : type.type_arguments )
            if ( typeDiscipline(package, element, visiting) == ValueDiscipline::Affine )
                return ValueDiscipline::Affine;

    visiting.erase(id.index);
    return ValueDiscipline::Copyable;
}

} // namespace

ValueDiscipline typeDiscipline(const Package& package, TypeId id) {
    std::unordered_set<uint32_t> visiting;
    return typeDiscipline(package, id, visiting);
}

std::optional<ParserOperationContract> parserContractFor(const Package& package, const Inst& inst) {
    const auto* schema = schemaFor(inst.opcode);
    if ( ! schema || ! schema->parser_contract )
        return std::nullopt;

    auto contract = *schema->parser_contract;
    if ( inst.opcode == Opcode::ReadInteger ) {
        if ( const auto* read = std::get_if<ReadIntegerPayload>(&inst.payload) )
            contract.success_consumption_bytes = read->width / 8;
    }
    else if ( inst.opcode == Opcode::ReadBytes && inst.args.size() == 2 && package.isValid(inst.args[1]) ) {
        const auto& length = package.inst(inst.args[1]);
        const auto* literal = std::get_if<IntegerLiteral>(&length.payload);
        if ( length.opcode == Opcode::IntConstant && literal && literal->bits <= INT64_MAX )
            contract.success_consumption_bytes = static_cast<int64_t>(literal->bits);
    }

    return contract;
}

bool conversionAccepts(const Package& package, ConversionRule rule, TypeId from, TypeId to) {
    if ( ! package.isValid(from) || ! package.isValid(to) || package.type(from).kind != TypeKind::Integer )
        return false;

    const auto& source = package.type(from).integer;
    const auto& target = package.type(to);
    switch ( rule ) {
        case ConversionRule::IntegerWiden:
            // Any wider integer holds every unsigned value, but only a signed one holds every signed value.
            return target.kind == TypeKind::Integer && target.integer.width > source.width &&
                   (source.signedness == Signedness::Unsigned || target.integer.signedness == Signedness::Signed);
        case ConversionRule::IntegerToBool: return target.kind == TypeKind::Bool;
    }

    return false;
}

OperandRole operandRole(const Package& package, const Inst& inst, size_t index) {
    if ( inst.opcode == Opcode::Call ) {
        const auto* payload = std::get_if<FunctionPayload>(&inst.payload);
        if ( ! payload || ! package.isValid(payload->function) )
            return OperandRole::Borrow;

        const auto& callee = package.function(payload->function);
        if ( index >= callee.parameters.size() )
            return OperandRole::Borrow;

        const auto& parameter = callee.parameters[index];
        if ( parameter.mode == ParameterMode::Take &&
             typeDiscipline(package, parameter.type) == ValueDiscipline::Affine )
            return OperandRole::Consume;
        return OperandRole::Borrow;
    }

    const auto* schema = schemaFor(inst.opcode);
    if ( ! schema || schema->operand_roles.empty() )
        return OperandRole::Borrow;
    return schema->operand_roles[std::min(index, schema->operand_roles.size() - 1)];
}

} // namespace spicy::detail::pir::ir
