// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <cstdint>
#include <limits>
#include <optional>
#include <variant>

#include <spicy/compiler/detail/pir/ir/builder.h>
#include <spicy/compiler/detail/pir/ir/cfg.h>
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

        case Opcode::Convert: {
            const auto rule = std::get<ConversionPayload>(inst.payload).rule;
            if ( auto value = integerConstant(package, inst.args[0]) ) {
                switch ( rule ) {
                    case ConversionRule::IntegerWiden: {
                        // A wider integer holds the same value, sign-extended if the source is signed.
                        auto bits = static_cast<uint64_t>(signedValue(value->bits, value->type));
                        auto width = package.type(inst.result_type).integer.width;
                        package.replaceInst(id,
                                            Opcode::IntConstant,
                                            {},
                                            InstPayload(IntegerLiteral{truncateBits(bits, width)}));
                        return true;
                    }
                    case ConversionRule::IntegerToBool:
                        package.replaceInst(id, Opcode::BoolConstant, {}, InstPayload(BoolLiteral{value->bits != 0}));
                        return true;
                }
            }

            // Two widenings in a row are one widening of the original value.
            const auto& operand = package.inst(inst.args[0]);
            if ( rule == ConversionRule::IntegerWiden && operand.opcode == Opcode::Convert &&
                 operand.args.size() == 1 &&
                 std::get<ConversionPayload>(operand.payload).rule == ConversionRule::IntegerWiden ) {
                auto source = operand.args[0];
                package.replaceInst(id, Opcode::Convert, {source}, InstPayload(ConversionPayload{rule}));
                return true;
            }

            return false;
        }

        default: return false;
    }
}

// A branch or switch on a constant becomes a jump to the target it always takes.
bool foldTerminator(Package& package, BlockId block) {
    const auto& insts = package.block(block).insts;
    if ( insts.empty() )
        return false;

    auto id = insts.back();
    const auto& inst = package.inst(id);
    std::optional<BlockId> target;
    if ( inst.opcode == Opcode::Branch && inst.args.size() == 1 ) {
        const auto& payload = std::get<BranchPayload>(inst.payload);
        if ( auto condition = boolConstant(package, inst.args[0]) )
            target = *condition ? payload.then_block : payload.else_block;
    }
    else if ( inst.opcode == Opcode::Switch && inst.args.size() == 1 ) {
        const auto& payload = std::get<SwitchPayload>(inst.payload);
        if ( auto value = integerConstant(package, inst.args[0]) ) {
            target = payload.default_target;
            for ( const auto& c : payload.cases )
                if ( c.value.bits == value->bits ) {
                    target = c.target;
                    break;
                }
        }
    }

    if ( ! target )
        return false;

    package.replaceInst(id, Opcode::Jump, {}, InstPayload(JumpPayload{*target}));
    return true;
}

// Erases the blocks of `region` that its entry no longer reaches, and the Upsilons that write a Phi erased with them.
void eraseUnreachable(Package& package, RegionId region) {
    auto cfg = buildCfg(package, region);
    if ( cfg.blocks.empty() )
        return;

    std::vector<bool> reachable(cfg.blocks.size(), false);
    for ( auto pos : postorder(cfg.successors, 0) )
        reachable[pos] = true;

    for ( size_t pos = 0; pos < cfg.blocks.size(); ++pos )
        if ( ! reachable[pos] )
            package.eraseBlock(region, cfg.blocks[pos]);

    for ( auto block : package.region(region).blocks )
        for ( auto id : std::vector<InstId>(package.block(block).insts) ) {
            const auto* upsilon = std::get_if<UpsilonPayload>(&package.inst(id).payload);
            if ( upsilon && package.isErased(upsilon->phi) )
                package.eraseInst(id);
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

    // A constant condition can make blocks unreachable. Their values have no uses elsewhere, since a reachable use
    // would need a reachable definition to dominate it.
    bool folded_control = false;
    for ( auto block_id : std::vector<BlockId>(package.region(fn.root_region).blocks) )
        folded_control = foldTerminator(package, block_id) || folded_control;

    if ( folded_control )
        eraseUnreachable(package, fn.root_region);

    return changed || folded_control;
}

} // namespace spicy::detail::pir::passes
