// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <unordered_map>
#include <unordered_set>
#include <variant>

#include <spicy/compiler/detail/pir/ir/printer.h>
#include <spicy/compiler/detail/pir/ir/reachability.h>
#include <spicy/compiler/detail/pir/ir/verifier.h>

namespace spicy::detail::pir::ir {

namespace {

// The affine discipline of an actual instantiated type: a `Tuple` inherits affine discipline from
// any element that itself has it (e.g. `tuple<parser.state, uint8>`), recursively.
ValueDiscipline typeDiscipline(const Package& package, TypeId id) {
    if ( ! package.isValid(id) )
        return ValueDiscipline::Copyable;

    const auto& type = package.type(id);
    if ( typeKindDiscipline(type.kind) == ValueDiscipline::Affine )
        return ValueDiscipline::Affine;

    if ( type.kind == TypeKind::Tuple )
        for ( auto element : type.type_arguments )
            if ( typeDiscipline(package, element) == ValueDiscipline::Affine )
                return ValueDiscipline::Affine;

    return ValueDiscipline::Copyable;
}

// This class's size (type/declaration verification alongside function, argument, opcode, and
// affinity verification) is architectural pressure, not a present correctness problem: nothing
// here is wrong, but a later slice may want type verification split into its own component.
// Deferred to the Step 5 cleanup rather than done speculatively now (see PLAN-parser-ir-3.md).
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

        _verifyFunctionKind(id, fn);

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

            _verifyBlock(id, block_id, fn);
        }
    }

    // Independent of `verifyTypeDecl()`'s per-declaration walk from each `TypeDecl`'s own `fields`
    // list: this iterates the `Declaration` arena directly and checks the *other* direction, so a
    // declaration that is orphaned (owner never lists it) or double-listed (appears more than once
    // in its owner's membership vector) is caught even if every individual field's cached `owner`
    // still looks consistent.
    void verifyDeclarationMembership() {
        std::unordered_map<uint32_t, uint32_t> membership_count;
        for ( size_t i = 0; i < _package.typeDecls().size(); ++i ) {
            auto id = TypeDeclId{static_cast<uint32_t>(i)};
            for ( auto field_id : _package.typeDecl(id).fields )
                if ( _package.isValid(field_id) )
                    ++membership_count[field_id.index];
        }

        for ( size_t i = 0; i < _package.declarations().size(); ++i ) {
            auto id = DeclId{static_cast<uint32_t>(i)};
            const auto& decl = _package.declaration(id);

            if ( ! _package.isValid(decl.owner) ) {
                _emitter.emit(diag::DeclarationInvalidOwner, id);
                continue;
            }

            auto it = membership_count.find(id.index);
            auto count = it != membership_count.end() ? it->second : 0;

            if ( count == 0 )
                _emitter.emit(diag::DeclarationNotInOwnerMembership, id);
            else if ( count > 1 )
                _emitter.emit(diag::DeclarationDuplicateOwnerMembership, id);
        }
    }

    void verifyParserRoot(const ParserRoot& root) {
        if ( ! _package.isValid(root.unit) ) {
            _emitter.emit(diag::InvalidParserRootUnit, noSite());
            return;
        }

        if ( ! _package.isValid(root.function) ) {
            _emitter.emit(diag::InvalidParserRootFunction, root.unit);
            return;
        }

        const auto& fn = _package.function(root.function);
        if ( fn.kind != FunctionKind::Parser ) {
            _emitter.emit(diag::ParserRootFunctionKindMismatch, root.function);
            return;
        }

        if ( fn.parser_unit != root.unit )
            _emitter.emit(diag::ParserRootUnitMismatch, root.function);
    }

private:
    // Layer 3: function kind/signature/parser-unit consistency.
    void _verifyFunctionKind(FunctionId id, const Function& fn) {
        if ( fn.kind == FunctionKind::Normal ) {
            if ( fn.parser_unit.isSet() )
                _emitter.emit(diag::NormalFunctionWithParserUnit, id);
            return;
        }

        if ( ! _package.isValid(fn.parser_unit) ) {
            _emitter.emit(diag::ParserFunctionMissingParserUnit, id);
            return;
        }

        if ( fn.parameters.size() != 1 )
            _emitter.emit(diag::ParserFunctionParameterCountMismatch, id, fn.parameters.size());
        else if ( ! _package.isValid(fn.parameters[0]) ||
                  _package.type(fn.parameters[0]).kind != TypeKind::ParserState )
            _emitter.emit(diag::ParserFunctionParameterTypeMismatch, id);

        if ( _package.isValid(fn.result_type) ) {
            const auto& result = _package.type(fn.result_type);
            if ( result.kind != TypeKind::Unit || result.declaration != fn.parser_unit )
                _emitter.emit(diag::ParserFunctionResultTypeMismatch, id);
        }
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

    void _verifyBlock(FunctionId function_id, BlockId block_id, const Function& fn) {
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

            _verifyInst(function_id, inst_id, block_id, i == block.insts.size() - 1, defined, fn.result_type);
            defined.insert(inst_id.index);
        }

        _verifyArgumentPrefix(function_id, block_id, fn);
        _verifyParserStateAffinity(function_id, block_id);
        _verifyUnitStateAffinity(function_id, block_id, fn);
    }

    // Layer 4: every `core.argument` in the entry block appears before any non-argument
    // instruction, indices are 0..N-1 with no gaps or duplicates, and N matches the function's
    // parameter count.
    void _verifyArgumentPrefix(FunctionId function_id, BlockId block_id, const Function& fn) {
        const auto& block = _package.block(block_id);

        std::unordered_set<uint32_t> seen_indices;
        bool prefix_ended = false;

        for ( auto inst_id : block.insts ) {
            if ( ! _package.isValid(inst_id) )
                continue;

            const auto& inst = _package.inst(inst_id);
            if ( inst.opcode != Opcode::Argument ) {
                prefix_ended = true;
                continue;
            }

            if ( prefix_ended ) {
                _emitter.emit(diag::ArgumentNotLeading, inst_id);
                continue;
            }

            const auto* payload = std::get_if<ArgumentPayload>(&inst.payload);
            if ( ! payload )
                continue; // reported generically as a payload-shape mismatch already

            if ( payload->index >= fn.parameters.size() ) {
                _emitter.emit(diag::ArgumentIndexOutOfRange, inst_id, payload->index, fn.parameters.size());
                continue;
            }

            if ( ! seen_indices.insert(payload->index).second )
                _emitter.emit(diag::ArgumentIndexDuplicate, inst_id, payload->index);
        }

        for ( size_t i = 0; i < fn.parameters.size(); ++i )
            if ( ! seen_indices.contains(static_cast<uint32_t>(i)) )
                _emitter.emit(diag::ArgumentIndexMissing, function_id, i);
    }

    // Layer 6: parser-state affinity, not a general affine-value framework. This still
    // special-cases `Opcode::TupleGet` directly (rather than treating it through a generic
    // `OperandRole::Forward` rule), and only enforces `OperandRole::Consume` for operands whose
    // immediate type is `ParserState`; unit affinity is a separate, richer scan in
    // `_verifyUnitStateAffinity()`. A use-count keyed only by the consumed `InstId` cannot see two
    // `core.tuple_get(read, 0)` projections of the same read as a fork of one logical state, since
    // each projection is itself a distinct, once-consumed `InstId`. This closes that hole in two
    // parts: (1) each `(tuple-producing instruction, element index)` pair whose selected element is
    // affine may be projected by `core.tuple_get` at most once; and (2) each resulting affine
    // `parser.state` value, wherever produced, may reach at most one `OperandRole::Consume`
    // operand. Generalizing this to every affine type and forwarding opcode is deferred until a
    // second affine type or forwarding opcode actually needs it (see PLAN-parser-ir-3.md).
    void _verifyParserStateAffinity(FunctionId /* function_id */, BlockId block_id) {
        const auto& block = _package.block(block_id);

        std::unordered_map<uint32_t, InstId> consumed_by;
        std::unordered_map<uint64_t, InstId> projected_by;

        auto slotKey = [](InstId tuple_inst, uint32_t index) -> uint64_t {
            return (static_cast<uint64_t>(tuple_inst.index) << 32) | index;
        };

        for ( auto inst_id : block.insts ) {
            if ( ! _package.isValid(inst_id) )
                continue;

            const auto& inst = _package.inst(inst_id);

            if ( inst.opcode == Opcode::TupleGet ) {
                const auto* payload = std::get_if<TupleGetPayload>(&inst.payload);
                if ( ! payload || inst.args.empty() || ! _package.isValid(inst.args[0]) )
                    continue;

                if ( typeDiscipline(_package, inst.result_type) != ValueDiscipline::Affine )
                    continue;

                auto [it, inserted] = projected_by.try_emplace(slotKey(inst.args[0], payload->index), inst_id);
                if ( ! inserted )
                    _emitter.emit(diag::ParserStateReused, inst_id);
                continue;
            }

            auto* schema = schemaFor(inst.opcode);
            if ( ! schema )
                continue;

            for ( size_t a = 0; a < inst.args.size() && a < schema->operand_roles.size(); ++a ) {
                if ( schema->operand_roles[a] != OperandRole::Consume )
                    continue;

                auto arg = inst.args[a];
                if ( ! _package.isValid(arg) )
                    continue;

                auto result_type = _package.inst(arg).result_type;
                if ( ! _package.isValid(result_type) || _package.type(result_type).kind != TypeKind::ParserState )
                    continue; // unit affinity has its own richer check in _verifyUnitStateAffinity

                auto [it, inserted] = consumed_by.try_emplace(arg.index, inst_id);
                if ( ! inserted )
                    _emitter.emit(diag::ParserStateReused, inst_id);
            }
        }
    }

    // Layer 7: tracks each unit value's publication chain from `unit.create` through
    // `unit.publish_field` to `parser.finish`, as a direct per-function scan. Straight-line
    // affinity checking is sufficient here; a general dataflow framework is deferred until PIR
    // actually has CFG joins or loops to reason about, not introduced speculatively for this
    // slice's single straight-line block.
    void _verifyUnitStateAffinity(FunctionId /* function_id */, BlockId block_id, const Function& fn) {
        const auto& block = _package.block(block_id);

        // Maps a unit.create's InstId to the current head of its publication chain, and the set
        // of field DeclIds published so far along that chain.
        struct Chain {
            InstId head;
            std::unordered_set<uint32_t> published;
        };
        std::vector<Chain> chains;

        auto findChain = [&](InstId value) -> Chain* {
            for ( auto& chain : chains )
                if ( chain.head == value )
                    return &chain;
            return nullptr;
        };

        for ( auto inst_id : block.insts ) {
            if ( ! _package.isValid(inst_id) )
                continue;

            const auto& inst = _package.inst(inst_id);

            if ( inst.opcode == Opcode::UnitCreate ) {
                chains.push_back(Chain{.head = inst_id, .published = {}});
                continue;
            }

            if ( inst.opcode == Opcode::PublishField ) {
                if ( inst.args.empty() || ! _package.isValid(inst.args[0]) )
                    continue;

                auto* chain = findChain(inst.args[0]);
                if ( ! chain ) {
                    _emitter.emit(diag::UnitStateStaleOrUnknownOperand, inst_id);
                    continue;
                }

                const auto* payload = std::get_if<FieldPayload>(&inst.payload);
                if ( payload && _package.isValid(payload->field) ) {
                    if ( ! chain->published.insert(payload->field.index).second )
                        _emitter.emit(diag::DuplicateFieldPublication, inst_id);
                }

                chain->head = inst_id;
                continue;
            }

            if ( inst.opcode == Opcode::Finish ) {
                if ( inst.args.size() < 2 || ! _package.isValid(inst.args[1]) )
                    continue;

                auto* chain = findChain(inst.args[1]);
                if ( ! chain ) {
                    _emitter.emit(diag::UnitStateStaleOrUnknownOperand, inst_id);
                    continue;
                }

                if ( _package.isValid(fn.parser_unit) ) {
                    for ( auto field_id : _package.typeDecl(fn.parser_unit).fields )
                        if ( ! chain->published.contains(field_id.index) )
                            _emitter.emit(diag::MissingFieldPublication, inst_id);
                }
            }
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

        auto* schema = schemaFor(inst.opcode);
        if ( ! schema ) {
            _emitter.emit(diag::UnrecognizedOpcode, inst_id);
            return;
        }

        if ( schema->is_terminator && ! is_last_in_block )
            _emitter.emit(diag::TerminatorNotLast, inst_id);

        if ( ! schema->is_terminator && is_last_in_block )
            _emitter.emit(diag::MissingTerminator, block_id);

        if ( inst.args.size() != schema->operandCount() )
            _emitter.emit(diag::OperandCountMismatch, inst_id, schema->operandCount(), inst.args.size());

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
        _verifyOpcodeSpecific(function_id, inst_id, inst);
    }

    // Layer 5 (dynamic part): result/operand construction that depends on payload content or on
    // the operand's actual structural type, which a static `TypeConstraint` cannot express.
    void _verifyOpcodeSpecific(FunctionId function_id, InstId inst_id, const Inst& inst) {
        switch ( inst.opcode ) {
            case Opcode::Finish: {
                if ( _package.isValid(function_id) && _package.function(function_id).kind != FunctionKind::Parser )
                    _emitter.emit(diag::FinishInNormalFunction, inst_id);
                return;
            }

            case Opcode::Argument: {
                const auto* payload = std::get_if<ArgumentPayload>(&inst.payload);
                if ( ! payload || ! _package.isValid(function_id) )
                    return;

                const auto& fn = _package.function(function_id);
                if ( payload->index < fn.parameters.size() && inst.result_type != fn.parameters[payload->index] )
                    _emitter.emit(diag::ArgumentResultTypeMismatch, inst_id);
                return;
            }

            case Opcode::TupleGet: {
                const auto* payload = std::get_if<TupleGetPayload>(&inst.payload);
                if ( ! payload || inst.args.empty() || ! _package.isValid(inst.args[0]) )
                    return;

                const auto& operand_inst = _package.inst(inst.args[0]);
                if ( ! _package.isValid(operand_inst.result_type) )
                    return;

                const auto& operand_type = _package.type(operand_inst.result_type);
                if ( operand_type.kind != TypeKind::Tuple ) {
                    _emitter.emit(diag::TupleGetOperandNotTuple, inst_id);
                    return;
                }

                if ( payload->index >= operand_type.type_arguments.size() ) {
                    _emitter.emit(diag::TupleGetIndexOutOfRange,
                                  inst_id,
                                  payload->index,
                                  operand_type.type_arguments.size());
                    return;
                }

                if ( inst.result_type != operand_type.type_arguments[payload->index] )
                    _emitter.emit(diag::TupleGetResultTypeMismatch, inst_id);
                return;
            }

            case Opcode::UnitCreate: {
                const auto* payload = std::get_if<UnitPayload>(&inst.payload);
                if ( ! payload )
                    return;

                if ( ! _package.isValid(payload->unit) ) {
                    _emitter.emit(diag::UnitCreateInvalidPayload, inst_id);
                    return;
                }

                if ( ! _package.isValid(inst.result_type) || _package.type(inst.result_type).kind != TypeKind::Unit ||
                     _package.type(inst.result_type).declaration != payload->unit )
                    _emitter.emit(diag::UnitCreateResultTypeMismatch, inst_id);
                return;
            }

            case Opcode::ReadInteger: {
                const auto* payload = std::get_if<ReadIntegerPayload>(&inst.payload);
                if ( ! payload )
                    return;

                if ( payload->width != 8 || payload->signedness != Signedness::Unsigned ||
                     payload->byte_order != ByteOrder::Network )
                    _emitter.emit(diag::ReadIntegerUnsupportedPayload, inst_id);

                bool result_ok = _package.isValid(inst.result_type);
                if ( result_ok ) {
                    const auto& result = _package.type(inst.result_type);
                    result_ok = result.kind == TypeKind::Tuple && result.type_arguments.size() == 2 &&
                                _package.isValid(result.type_arguments[0]) &&
                                _package.type(result.type_arguments[0]).kind == TypeKind::ParserState &&
                                _package.isValid(result.type_arguments[1]) &&
                                _package.type(result.type_arguments[1]).kind == TypeKind::UInt8;
                }

                if ( ! result_ok )
                    _emitter.emit(diag::ReadIntegerResultTypeMismatch, inst_id);
                return;
            }

            case Opcode::PublishField: {
                const auto* payload = std::get_if<FieldPayload>(&inst.payload);
                if ( ! payload || inst.args.size() < 2 )
                    return;

                if ( ! _package.isValid(payload->field) ) {
                    _emitter.emit(diag::PublishFieldInvalidPayload, inst_id);
                    return;
                }

                const auto& field = _package.declaration(payload->field);

                if ( ! _package.isValid(inst.args[0]) )
                    return;

                const auto& unit_operand = _package.inst(inst.args[0]);
                if ( ! _package.isValid(unit_operand.result_type) ||
                     _package.type(unit_operand.result_type).kind != TypeKind::Unit ) {
                    _emitter.emit(diag::PublishFieldOperandNotUnit, inst_id);
                    return;
                }

                if ( _package.type(unit_operand.result_type).declaration != field.owner )
                    _emitter.emit(diag::PublishFieldOwnerMismatch, inst_id);

                if ( _package.isValid(inst.args[1]) && _package.inst(inst.args[1]).result_type != field.type )
                    _emitter.emit(diag::PublishFieldValueTypeMismatch, inst_id);
                return;
            }

            default: return;
        }
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

    verifier.verifyDeclarationMembership();

    for ( size_t i = 0; i < package.functions().size(); ++i ) {
        auto id = FunctionId{static_cast<uint32_t>(i)};
        verifier.verifyFunction(id, package.function(id));
    }

    std::unordered_set<uint32_t> parser_root_units;
    for ( const auto& root : package.parserRoots() ) {
        if ( root.unit.isSet() && ! parser_root_units.insert(root.unit.index).second )
            emitter.emit(diag::DuplicateParserRootUnit, root.unit);

        verifier.verifyParserRoot(root);
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
