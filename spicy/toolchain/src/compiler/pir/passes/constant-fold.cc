// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <cstdint>
#include <limits>
#include <optional>
#include <variant>

#include <spicy/compiler/detail/pir/ir/builder.h>
#include <spicy/compiler/detail/pir/passes/constant-fold.h>

using namespace spicy::detail::pir;
using namespace spicy::detail::pir::ir;

namespace {

// The value of an integer constant, with the integer type that gives it meaning.
struct Constant {
    uint64_t bits = 0;
    IntegerType type;
};

std::optional<Constant> integerConstant(const Package& package, InstId id) {
    if ( ! package.isValid(id) )
        return {};

    const auto& inst = package.inst(id);
    if ( inst.opcode != Opcode::IntConstant || ! package.isValid(inst.result_type) ||
         package.type(inst.result_type).kind != TypeKind::Integer )
        return {};

    if ( const auto* literal = std::get_if<IntegerLiteral>(&inst.payload) )
        return Constant{.bits = literal->bits, .type = package.type(inst.result_type).integer};

    return {};
}

std::optional<bool> boolConstant(const Package& package, InstId id) {
    if ( ! package.isValid(id) || package.inst(id).opcode != Opcode::BoolConstant )
        return {};

    if ( const auto* literal = std::get_if<BoolLiteral>(&package.inst(id).payload) )
        return literal->value;

    return {};
}

// The sum in the operands' type, or nothing if it overflows. An overflow is left to fail at runtime.
std::optional<uint64_t> checkedAdd(Constant a, Constant b) {
    const auto width = a.type.width;
    if ( a.type.signedness == Signedness::Unsigned ) {
        const auto max = truncateBits(std::numeric_limits<uint64_t>::max(), width);
        if ( a.bits > max - b.bits )
            return {};
        return a.bits + b.bits;
    }

    const auto max = static_cast<int64_t>(truncateBits(std::numeric_limits<uint64_t>::max(), width - 1));
    const auto min = -max - 1;
    const auto x = signedValue(a.bits, a.type);
    const auto y = signedValue(b.bits, b.type);
    if ( y >= 0 ? x > max - y : x < min - y )
        return {};
    return truncateBits(static_cast<uint64_t>(x + y), width);
}

bool foldInst(Package& package, InstId id) {
    const auto& inst = package.inst(id);
    const auto* schema = schemaFor(inst.opcode);
    if ( ! schema || inst.args.size() != schema->operandCount() )
        return false;

    switch ( inst.opcode ) {
        case Opcode::Add: {
            auto lhs = integerConstant(package, inst.args[0]);
            auto rhs = integerConstant(package, inst.args[1]);
            if ( ! lhs || ! rhs || lhs->type != rhs->type )
                return false;

            auto sum = checkedAdd(*lhs, *rhs);
            if ( ! sum )
                return false;

            package.replaceInst(id, Opcode::IntConstant, {}, InstPayload(IntegerLiteral{*sum}));
            return true;
        }

        case Opcode::Equal: {
            std::optional<bool> equal;
            if ( auto lhs = integerConstant(package, inst.args[0]) ) {
                if ( auto rhs = integerConstant(package, inst.args[1]); rhs && lhs->type == rhs->type )
                    equal = lhs->bits == rhs->bits;
            }
            else if ( auto lhs = boolConstant(package, inst.args[0]) ) {
                if ( auto rhs = boolConstant(package, inst.args[1]) )
                    equal = *lhs == *rhs;
            }

            if ( ! equal )
                return false;

            package.replaceInst(id, Opcode::BoolConstant, {}, InstPayload(BoolLiteral{*equal}));
            return true;
        }

        default: return false;
    }
}

} // namespace

namespace spicy::detail::pir::passes {

bool foldConstants(Package& package, FunctionId function) {
    if ( ! package.isValid(function) )
        return false;

    bool changed = false;

    const auto& fn = package.function(function);
    if ( ! package.isValid(fn.root_region) )
        return false;

    for ( auto block_id : package.region(fn.root_region).blocks ) {
        if ( ! package.isValid(block_id) )
            continue;

        // Operands come before their uses, so one pass in order folds chains of constants.
        auto insts = package.block(block_id).insts;
        for ( auto inst_id : insts )
            changed = foldInst(package, inst_id) || changed;
    }

    return changed;
}

} // namespace spicy::detail::pir::passes
