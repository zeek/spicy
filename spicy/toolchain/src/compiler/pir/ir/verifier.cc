// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <unordered_set>
#include <variant>

#include <spicy/compiler/detail/pir/ir/printer.h>
#include <spicy/compiler/detail/pir/ir/reachability.h>
#include <spicy/compiler/detail/pir/ir/verifier.h>

namespace spicy::detail::pir::ir {

namespace {

class Verifier {
public:
    Verifier(const Package& package, std::vector<Diagnostic>& diags) : _package(package), _emitter(package, diags) {}

    void verifyType(TypeId id, const Type& type) {
        if ( type.kind == TypeKind::Unit ) {
            if ( ! _package.isValid(type.declaration) )
                _emitter.emit(diag::TypeMissingDeclaration, id);
        }
        else if ( type.declaration.isSet() )
            _emitter.emit(diag::TypeUnexpectedDeclaration, id);

        if ( type.kind == TypeKind::Tuple ) {
            for ( size_t a = 0; a < type.type_arguments.size(); ++a )
                if ( ! _package.isValid(type.type_arguments[a]) )
                    _emitter.emit(diag::TypeInvalidTypeArgument, id, a);
        }
        else if ( ! type.type_arguments.empty() )
            _emitter.emit(diag::TypeUnexpectedTypeArguments, id);
    }

    void verifyTypeDecl(TypeDeclId id, const TypeDecl& decl) {
        _verifySpan(decl.span, id);

        for ( auto field_id : decl.fields ) {
            if ( ! _package.isValid(field_id) ) {
                _emitter.emit(diag::InvalidFieldDeclarationId, id);
                continue;
            }

            const auto& field = _package.declaration(field_id);
            if ( field.owner != id )
                _emitter.emit(diag::FieldOwnerMismatch, field_id);

            _verifySpan(field.span, field_id);

            if ( ! _package.isValid(field.type) )
                _emitter.emit(diag::InvalidFieldType, field_id);
        }
    }

    void verifyFunction(FunctionId id, const Function& fn) {
        _verifySpan(fn.span, id);

        if ( ! _package.isValid(fn.result_type) )
            _emitter.emit(diag::InvalidFunctionResultType, id);

        if ( ! _package.isValid(fn.root_region) ) {
            _emitter.emit(diag::InvalidRootRegion, id);
            return;
        }

        const auto& region = _package.region(fn.root_region);
        if ( region.blocks.size() != 1 )
            _emitter.emit(diag::RegionBlockCountMismatch, id, region.blocks.size());

        for ( auto block_id : region.blocks ) {
            if ( ! _package.isValid(block_id) ) {
                _emitter.emit(diag::InvalidBlockId, id);
                continue;
            }

            _verifyBlock(id, block_id, fn.result_type);
        }
    }

private:
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

    template<typename Anchor>
    void _verifySpan(SourceSpanId span, const Anchor& site) {
        if ( ! span.isSet() )
            return;

        const auto& sources = _package.sourceManager();
        if ( ! sources.isValid(span) ) {
            _emitter.emit(diag::InvalidSourceSpanId, site);
            return;
        }

        const auto& s = sources.span(span);
        if ( ! sources.isValid(s.file) )
            _emitter.emit(diag::InvalidSourceFileId, site);

        if ( s.begin_line >= 0 && s.end_line >= 0 && s.begin_line == s.end_line && s.begin_column >= 0 &&
             s.end_column >= 0 && s.end_column < s.begin_column )
            _emitter.emit(diag::MalformedSourceSpanRange, site, "column");

        if ( s.begin_line >= 0 && s.end_line >= 0 && s.end_line < s.begin_line )
            _emitter.emit(diag::MalformedSourceSpanRange, site, "line");
    }

    void _verifyBlock(FunctionId function_id, BlockId block_id, TypeId function_result_type) {
        const auto& block = _package.block(block_id);
        if ( block.insts.empty() ) {
            _emitter.emit(diag::EmptyBlock, block_id);
            return;
        }

        std::unordered_set<uint32_t> defined;

        for ( size_t i = 0; i < block.insts.size(); ++i ) {
            auto inst_id = block.insts[i];
            if ( ! _package.isValid(inst_id) ) {
                _emitter.emit(diag::InvalidInstructionId, block_id, i);
                continue;
            }

            _verifyInst(function_id, inst_id, block_id, i == block.insts.size() - 1, defined, function_result_type);
            defined.insert(inst_id.index);
        }
    }

    void _verifyInst(FunctionId function_id,
                     InstId inst_id,
                     BlockId block_id,
                     bool is_last_in_block,
                     const std::unordered_set<uint32_t>& defined,
                     TypeId function_result_type) {
        const auto& inst = _package.inst(inst_id);

        _verifySpan(inst.span, inst_id);

        if ( inst.parent != block_id )
            _emitter.emit(diag::CachedParentMismatch, inst_id, inst.parent.index, block_id.index);

        auto schema = lookupSchema(inst.opcode);
        if ( ! schema ) {
            _emitter.emit(diag::UnrecognizedOpcode, inst_id);
            return;
        }

        if ( schema->is_terminator && ! is_last_in_block )
            _emitter.emit(diag::TerminatorNotLast, inst_id);

        if ( ! schema->is_terminator && is_last_in_block )
            _emitter.emit(diag::MissingTerminator, block_id);

        if ( inst.args.size() != schema->operand_count )
            _emitter.emit(diag::OperandCountMismatch, inst_id, schema->operand_count, inst.args.size());

        if ( ! payloadMatchesKind(inst.payload, schema->payload_kind) ) {
            if ( schema->payload_kind == PayloadKind::None )
                _emitter.emit(diag::UnexpectedPayload, inst_id);
            else
                _emitter.emit(diag::MissingPayload, inst_id);
        }

        for ( size_t a = 0; a < inst.args.size() && a < schema->operand_types.size(); ++a )
            _verifyOperand(function_id,
                           inst_id,
                           block_id,
                           schema->operand_types[a],
                           a,
                           inst.args[a],
                           defined,
                           function_result_type);

        _verifyResultType(inst_id, inst, *schema);
    }

    void _verifyOperand(FunctionId function_id,
                        InstId user,
                        BlockId block_id,
                        const TypeConstraint& constraint,
                        size_t operand_index,
                        InstId arg,
                        const std::unordered_set<uint32_t>& defined,
                        TypeId function_result_type) {
        if ( ! _package.isValid(arg) ) {
            _emitter.emit(diag::InvalidOperandId, user, operand_index);
            return;
        }

        const auto& arg_inst = _package.inst(arg);

        if ( arg_inst.parent != block_id ) {
            _emitter.emit(diag::OperandNotSameBlock, user, operand_index);
            return;
        }

        if ( ! defined.contains(arg.index) ) {
            _emitter.emit(diag::OperandUsedBeforeDefinition, user, operand_index);
            return;
        }

        if ( arg_inst.result_type == _package.voidType() )
            _emitter.emit(diag::VoidOperandUsed, user, operand_index);

        if ( ! _satisfies(constraint, arg_inst.result_type, function_result_type) ) {
            if ( constraint.kind == TypeConstraintKind::SameAsFunctionResult )
                _emitter
                    .emit(diag::ReturnTypeMismatch,
                          user,
                          typeName(_package, arg_inst.result_type),
                          typeName(_package, function_result_type))
                    .note(diag::FunctionDeclaredHere, function_id, typeName(_package, function_result_type));
            else
                _emitter.emit(diag::OperandTypeMismatch, user, operand_index).note(diag::OperandDefinedHere, arg);
        }
    }

    void _verifyResultType(InstId inst_id, const Inst& inst, const OpcodeSchema& schema) {
        switch ( schema.result_type.kind ) {
            case TypeConstraintKind::Any: return;

            case TypeConstraintKind::Fixed:
                if ( ! _satisfies(schema.result_type, inst.result_type, TypeId{}) )
                    _emitter.emit(diag::ResultTypeMismatch, inst_id);
                return;

            case TypeConstraintKind::SameAsOperand: {
                if ( inst.args.empty() )
                    return;

                auto operand = inst.args[0];
                if ( ! _package.isValid(operand) )
                    return;

                if ( inst.result_type != _package.inst(operand).result_type )
                    _emitter.emit(diag::ResultTypeMismatch, inst_id);
                return;
            }

            case TypeConstraintKind::SameAsFunctionResult: return;
        }
    }

    const Package& _package;
    DiagnosticEmitter _emitter;
};

} // namespace

std::vector<Diagnostic> verify(const Package& package) {
    std::vector<Diagnostic> diags;
    Verifier verifier(package, diags);
    DiagnosticEmitter emitter(package, diags);

    for ( size_t i = 0; i < package.types().size(); ++i ) {
        auto id = TypeId{static_cast<uint32_t>(i)};
        verifier.verifyType(id, package.type(id));
    }

    for ( size_t i = 0; i < package.typeDecls().size(); ++i ) {
        auto id = TypeDeclId{static_cast<uint32_t>(i)};
        verifier.verifyTypeDecl(id, package.typeDecl(id));
    }

    for ( size_t i = 0; i < package.functions().size(); ++i ) {
        auto id = FunctionId{static_cast<uint32_t>(i)};
        verifier.verifyFunction(id, package.function(id));
    }

    auto reach = computeReachableIds(package);

    for ( auto id : reach.duplicate_regions )
        emitter.emit(diag::DuplicateRegionOwnership, id);
    for ( auto id : reach.duplicate_blocks )
        emitter.emit(diag::DuplicateBlockOwnership, id);
    for ( auto id : reach.duplicate_insts )
        emitter.emit(diag::DuplicateInstructionOwnership, id);

    if ( reach.regions.size() != package.regions().size() )
        emitter.emit(diag::OrphanRegions, noSite(), package.regions().size() - reach.regions.size());
    if ( reach.blocks.size() != package.blocks().size() )
        emitter.emit(diag::OrphanBlocks, noSite(), package.blocks().size() - reach.blocks.size());
    if ( reach.insts.size() != package.instructions().size() )
        emitter.emit(diag::OrphanInstructions, noSite(), package.instructions().size() - reach.insts.size());

    return diags;
}

} // namespace spicy::detail::pir::ir
