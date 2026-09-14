// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <unordered_set>
#include <variant>

#include <hilti/base/util.h>

#include <spicy/compiler/detail/pir/ir/reachability.h>
#include <spicy/compiler/detail/pir/ir/verifier.h>

using hilti::util::fmt;

namespace spicy::detail::pir::ir {

namespace {

class Verifier {
public:
    Verifier(const Package& package, std::vector<Diagnostic>& diags) : _package(package), _diags(diags) {}

    void _verifyFunction(const Function& fn) {
        if ( ! _package.isValid(fn.result_type) )
            _fail(DiagnosticCode::InvalidFunctionResultType,
                  fmt("function '%s': result type is not a valid type ID", fn.name));

        if ( ! _package.isValid(fn.root_region) ) {
            _fail(DiagnosticCode::InvalidRootRegion,
                  fmt("function '%s': root region is not a valid region ID", fn.name));
            return;
        }

        const auto& region = _package.region(fn.root_region);
        if ( region.blocks.size() != 1 )
            _fail(DiagnosticCode::RegionBlockCountMismatch,
                  fmt("function '%s': its region must contain exactly one block, has %zu",
                      fn.name,
                      region.blocks.size()));

        for ( auto block_id : region.blocks ) {
            if ( ! _package.isValid(block_id) ) {
                _fail(DiagnosticCode::InvalidBlockId,
                      fmt("function '%s': region references an invalid block ID", fn.name));
                continue;
            }

            _verifyBlock(block_id, fn.result_type);
        }
    }

private:
    void _fail(DiagnosticCode code, std::string message) {
        _diags.push_back(Diagnostic{.code = code, .message = std::move(message)});
    }

    bool _satisfies(const TypeConstraint& constraint, TypeId type_id, TypeId function_result_type) const {
        switch ( constraint.kind ) {
            case TypeConstraintKind::Any: return true;
            case TypeConstraintKind::Fixed:
                return _package.isValid(type_id) && _package.type(type_id).kind == constraint.fixed;
            case TypeConstraintKind::SameAsOperand: return false;
            case TypeConstraintKind::SameAsFunctionResult: return type_id == function_result_type;
        }

        return false;
    }

    void _verifyBlock(BlockId block_id, TypeId function_result_type) {
        const auto& block = _package.block(block_id);
        if ( block.insts.empty() ) {
            _fail(DiagnosticCode::EmptyBlock,
                  fmt("block %u has no instructions and therefore no terminator", block_id.index));
            return;
        }

        std::unordered_set<uint32_t> defined;

        for ( size_t i = 0; i < block.insts.size(); ++i ) {
            auto inst_id = block.insts[i];
            if ( ! _package.isValid(inst_id) ) {
                _fail(DiagnosticCode::InvalidInstructionId,
                      fmt("block %u: instruction at position %zu has an invalid ID", block_id.index, i));
                continue;
            }

            _verifyInst(inst_id, block_id, i == block.insts.size() - 1, defined, function_result_type);
            defined.insert(inst_id.index);
        }
    }

    void _verifyInst(InstId inst_id,
                     BlockId block_id,
                     bool is_last_in_block,
                     const std::unordered_set<uint32_t>& defined,
                     TypeId function_result_type) {
        const auto& inst = _package.inst(inst_id);

        if ( inst.parent != block_id )
            _fail(DiagnosticCode::CachedParentMismatch,
                  fmt("instruction %%%u: cached parent block does not match its containing block %u",
                      inst_id.index,
                      block_id.index));

        auto schema = lookupSchema(inst.opcode);
        if ( ! schema ) {
            _fail(DiagnosticCode::UnrecognizedOpcode, fmt("instruction %%%u: unrecognized opcode", inst_id.index));
            return;
        }

        if ( schema->is_terminator && ! is_last_in_block )
            _fail(DiagnosticCode::TerminatorNotLast,
                  fmt("instruction %%%u: terminator is not the last instruction in block %u",
                      inst_id.index,
                      block_id.index));

        if ( ! schema->is_terminator && is_last_in_block )
            _fail(DiagnosticCode::MissingTerminator, fmt("block %u does not end in a terminator", block_id.index));

        if ( inst.args.size() != schema->operand_count )
            _fail(DiagnosticCode::OperandCountMismatch,
                  fmt("instruction %%%u: expected %zu operand(s), got %zu",
                      inst_id.index,
                      schema->operand_count,
                      inst.args.size()));

        bool payload_is_int = std::holds_alternative<int64_t>(inst.payload);
        switch ( schema->payload_kind ) {
            case PayloadKind::None:
                if ( payload_is_int )
                    _fail(DiagnosticCode::UnexpectedPayload,
                          fmt("instruction %%%u: unexpected integer payload", inst_id.index));
                break;
            case PayloadKind::Int64Literal:
                if ( ! payload_is_int )
                    _fail(DiagnosticCode::MissingPayload,
                          fmt("instruction %%%u: missing required integer payload", inst_id.index));
                break;
        }

        for ( size_t a = 0; a < inst.args.size(); ++a )
            _verifyOperand(inst_id, block_id, schema->operand_type, a, inst.args[a], defined, function_result_type);

        _verifyResultType(inst_id, inst, *schema);
    }

    void _verifyOperand(InstId user,
                        BlockId block_id,
                        const TypeConstraint& constraint,
                        size_t operand_index,
                        InstId arg,
                        const std::unordered_set<uint32_t>& defined,
                        TypeId function_result_type) {
        if ( ! _package.isValid(arg) ) {
            _fail(DiagnosticCode::InvalidOperandId,
                  fmt("instruction %%%u: operand %zu is not a valid instruction ID", user.index, operand_index));
            return;
        }

        const auto& arg_inst = _package.inst(arg);

        if ( arg_inst.parent != block_id ) {
            _fail(DiagnosticCode::OperandNotSameBlock,
                  fmt("instruction %%%u: operand %zu (%%%u) is not defined in the same block",
                      user.index,
                      operand_index,
                      arg.index));
            return;
        }

        if ( ! defined.contains(arg.index) ) {
            _fail(DiagnosticCode::OperandUsedBeforeDefinition,
                  fmt("instruction %%%u: operand %zu (%%%u) is used before it is defined",
                      user.index,
                      operand_index,
                      arg.index));
            return;
        }

        if ( arg_inst.result_type == _package.voidType() )
            _fail(DiagnosticCode::VoidOperandUsed,
                  fmt("instruction %%%u: operand %zu (%%%u) has void type and cannot be used",
                      user.index,
                      operand_index,
                      arg.index));

        if ( ! _satisfies(constraint, arg_inst.result_type, function_result_type) ) {
            if ( constraint.kind == TypeConstraintKind::SameAsFunctionResult )
                _fail(DiagnosticCode::ReturnTypeMismatch,
                      fmt("instruction %%%u: returned value does not match the function's declared result type",
                          user.index));
            else
                _fail(DiagnosticCode::OperandTypeMismatch,
                      fmt("instruction %%%u: operand %zu (%%%u) does not satisfy its required type",
                          user.index,
                          operand_index,
                          arg.index));
        }
    }

    void _verifyResultType(InstId inst_id, const Inst& inst, const OpcodeSchema& schema) {
        switch ( schema.result_type.kind ) {
            case TypeConstraintKind::Any: return;

            case TypeConstraintKind::Fixed:
                if ( ! _satisfies(schema.result_type, inst.result_type, TypeId{}) )
                    _fail(DiagnosticCode::ResultTypeMismatch,
                          fmt("instruction %%%u: result type does not match its required type", inst_id.index));
                return;

            case TypeConstraintKind::SameAsOperand: {
                if ( inst.args.empty() )
                    return;

                auto operand = inst.args[0];
                if ( ! _package.isValid(operand) )
                    return;

                if ( inst.result_type != _package.inst(operand).result_type )
                    _fail(DiagnosticCode::ResultTypeMismatch,
                          fmt("instruction %%%u: result type must match operand 0's type", inst_id.index));
                return;
            }

            case TypeConstraintKind::SameAsFunctionResult: return;
        }
    }

    const Package& _package;
    std::vector<Diagnostic>& _diags;
};

void addDiagnostic(std::vector<Diagnostic>& diags, DiagnosticCode code, std::string message) {
    diags.push_back(Diagnostic{.code = code, .message = std::move(message)});
}

} // namespace

std::vector<Diagnostic> verify(const Package& package) {
    std::vector<Diagnostic> diags;
    Verifier verifier(package, diags);

    for ( const auto& fn : package.functions() )
        verifier._verifyFunction(fn);

    auto reach = computeReachableIds(package);

    for ( auto id : reach.duplicate_regions )
        addDiagnostic(diags,
                      DiagnosticCode::DuplicateRegionOwnership,
                      fmt("region %%%u is owned by more than one function", id.index));
    for ( auto id : reach.duplicate_blocks )
        addDiagnostic(diags,
                      DiagnosticCode::DuplicateBlockOwnership,
                      fmt("block %%%u belongs to more than one function's region", id.index));
    for ( auto id : reach.duplicate_insts )
        addDiagnostic(diags,
                      DiagnosticCode::DuplicateInstructionOwnership,
                      fmt("instruction %%%u belongs to more than one block", id.index));

    if ( reach.regions.size() != package.regions().size() )
        addDiagnostic(diags,
                      DiagnosticCode::OrphanRegions,
                      fmt("package contains %zu unattached region(s)",
                          package.regions().size() - reach.regions.size()));
    if ( reach.blocks.size() != package.blocks().size() )
        addDiagnostic(diags,
                      DiagnosticCode::OrphanBlocks,
                      fmt("package contains %zu unattached block(s)", package.blocks().size() - reach.blocks.size()));
    if ( reach.insts.size() != package.instructions().size() )
        addDiagnostic(diags,
                      DiagnosticCode::OrphanInstructions,
                      fmt("package contains %zu unattached instruction(s)",
                          package.instructions().size() - reach.insts.size()));

    return diags;
}

} // namespace spicy::detail::pir::ir
