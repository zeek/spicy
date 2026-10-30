// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <algorithm>
#include <unordered_set>
#include <utility>

#include <spicy/compiler/detail/pir/ir/builder.h>
#include <spicy/compiler/detail/pir/ir/package.h>

namespace spicy::detail::pir::ir {

Package::Package() {
    _void_type = _types.add(Type{.kind = TypeKind::Void});
    _int64_type = _types.add(Type{.kind = TypeKind::Int64});
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
