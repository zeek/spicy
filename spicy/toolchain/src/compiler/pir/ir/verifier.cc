// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <algorithm>
#include <unordered_map>
#include <unordered_set>
#include <variant>

#include <spicy/compiler/detail/pir/ir/cfg.h>
#include <spicy/compiler/detail/pir/ir/printer.h>
#include <spicy/compiler/detail/pir/ir/reachability.h>
#include <spicy/compiler/detail/pir/ir/verifier.h>

namespace spicy::detail::pir::ir {

namespace {

// The affine discipline of an actual instantiated type: a `Tuple` inherits affine discipline from
// any element that itself has it (e.g. `tuple<parser.state, uint8>`), recursively.
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

ValueDiscipline typeDiscipline(const Package& package, TypeId id) {
    std::unordered_set<uint32_t> visiting;
    return typeDiscipline(package, id, visiting);
}

// Kinda weird, just makes a unique key for tuple instruction + its index
// so we can check if this tuple instruction gets consumed multiple
// times from just a "key."
uint64_t slotKey(InstId tuple_inst, uint32_t index) { return (static_cast<uint64_t>(tuple_inst.index) << 32U) | index; }

class Verifier {
public:
    Verifier(const Package& package, std::vector<Diagnostic>& diags) : _package(package), _emitter(package, diags) {}

    void verifyType(TypeId id, const Type& type) {
        if ( type.kind == TypeKind::Unit ) {
            if ( ! _package.isValid(type.declaration) )
                _emitter.emit(diag::TypeMissingDeclaration, id);
        }
        else if ( type.kind == TypeKind::Opaque ) {
            if ( ! _package.isValid(type.declaration) ||
                 _package.typeDecl(type.declaration).kind != TypeDeclKind::Opaque )
                _emitter.emit(diag::TypeOpaqueMissingDeclaration, id);
        }
        else if ( type.declaration.isSet() )
            _emitter.emit(diag::TypeUnexpectedDeclaration, id);

        if ( type.kind == TypeKind::Tuple || type.kind == TypeKind::Vector ) {
            if ( type.kind == TypeKind::Vector && type.type_arguments.size() != 1 )
                _emitter.emit(diag::TypeUnexpectedTypeArguments, id);
            for ( size_t a = 0; a < type.type_arguments.size(); ++a ) {
                if ( ! _package.isValid(type.type_arguments[a]) )
                    _emitter.emit(diag::TypeInvalidTypeArgument, id, a);
                else if ( _package.type(type.type_arguments[a]).kind == TypeKind::Place )
                    _emitter.emit(diag::PlaceEscapes, id);
            }
        }
        else if ( type.kind == TypeKind::Place ) {
            if ( type.type_arguments.size() != 1 || ! _package.isValid(type.type_arguments[0]) )
                _emitter.emit(diag::PlaceMissingElement, id);
        }
        else if ( ! type.type_arguments.empty() )
            _emitter.emit(diag::TypeUnexpectedTypeArguments, id);
    }

    void verifyTypeDecl(TypeDeclId id, const TypeDecl& decl) {
        _verifySpan(decl.span, id);

        if ( decl.kind == TypeDeclKind::Opaque ) {
            if ( ! decl.opaque )
                _emitter.emit(diag::TypeDeclOpaqueInfoMismatch, id);
            else if ( decl.opaque->cxx_name.empty() || ! decl.opaque->lifecycle )
                _emitter.emit(diag::OpaqueDeclarationIncomplete, id);
        }
        else if ( decl.opaque )
            _emitter.emit(diag::TypeDeclOpaqueInfoMismatch, id);

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
            else if ( _package.type(field.type).kind == TypeKind::Place )
                _emitter.emit(diag::PlaceEscapes, field_id);
        }
    }

    void verifyForeignFunction(ForeignFunctionId id, const ForeignFunction& fn) {
        _verifySpan(fn.span, id);

        if ( fn.cxx_name.empty() )
            _emitter.emit(diag::ForeignFunctionMissingBinding, id);

        if ( ! _package.isValid(fn.result_type) || typeDiscipline(_package, fn.result_type) == ValueDiscipline::Affine )
            _emitter.emit(diag::ForeignFunctionInvalidResult, id);

        for ( size_t p = 0; p < fn.parameters.size(); ++p ) {
            const auto& parameter = fn.parameters[p];
            if ( parameter.argument != ForeignArgument::Value )
                continue;

            if ( ! _package.isValid(parameter.type) || parameter.type == _package.voidType() ||
                 typeDiscipline(_package, parameter.type) == ValueDiscipline::Affine )
                _emitter.emit(diag::ForeignFunctionInvalidParameter, id, p);
        }
    }

    // Whether a value of `type` is an opaque value whose native type declares no copy behavior.
    bool _isNonCopyableOpaque(TypeId type) const {
        if ( ! _package.isValid(type) || _package.type(type).kind != TypeKind::Opaque )
            return false;

        const auto& decl = _package.typeDecl(_package.type(type).declaration);
        return ! decl.opaque || ! decl.opaque->lifecycle || ! decl.opaque->lifecycle->copyable;
    }

    // Whether a native call may receive an operand of `type` for `parameter`, by its convention.
    bool _acceptsArgument(const ForeignParameter& parameter, TypeId type) const {
        if ( ! _package.isValid(type) )
            return false;

        switch ( parameter.argument ) {
            case ForeignArgument::Value: return type == parameter.type;
            case ForeignArgument::TypeInfo:
            case ForeignArgument::AnyPointer:
                return type != _package.voidType() && typeDiscipline(_package, type) == ValueDiscipline::Copyable;
            case ForeignArgument::AnyTuple: return _package.type(type).kind == TypeKind::Tuple;
        }

        return false;
    }

    void verifyFunction(FunctionId id, const Function& fn) {
        _verifySpan(fn.span, id);

        if ( ! _package.isValid(fn.result_type) )
            _emitter.emit(diag::InvalidFunctionResultType, id);
        else if ( _package.type(fn.result_type).kind == TypeKind::Place )
            _emitter.emit(diag::PlaceEscapes, id);

        if ( fn.kind == FunctionKind::Hook ) {
            // A hook takes exactly the unit it observes, and that unit is borrowed rather than consumed.
            if ( fn.parameters.size() != 1 || ! _package.isValid(fn.parameters[0]) ||
                 _package.type(fn.parameters[0]).kind != TypeKind::Unit )
                _emitter.emit(diag::NormalFunctionInvalidParameter, id, 0);
        }
        if ( fn.kind == FunctionKind::Normal ) {
            for ( size_t p = 0; p < fn.parameters.size(); ++p ) {
                auto parameter = fn.parameters[p];
                if ( ! _package.isValid(parameter) || parameter == _package.voidType() ||
                     typeDiscipline(_package, parameter) == ValueDiscipline::Affine )
                    _emitter.emit(diag::NormalFunctionInvalidParameter, id, p);
            }
        }

        _verifyFunctionKind(id, fn);

        if ( ! _package.isValid(fn.root_region) ) {
            _emitter.emit(diag::InvalidRootRegion, id);
            return;
        }

        if ( fn.kind == FunctionKind::Parser ) {
            _verifyRegion(id, fn.root_region, fn, {});
            return;
        }

        // An ordinary function's body is a CFG, so its blocks are checked against the dominator tree and its
        // affine values against all of its paths.
        _beginBody(id, fn);
        _verifyRegion(id, fn.root_region, fn, {});
        if ( ! _cfg.blocks.empty() )
            _verifyBodyAffinity();
        _endBody();
    }

    void _beginBody(FunctionId id, const Function& fn) {
        _cfg = buildCfg(_package, fn.root_region);
        _in_body = true;
        if ( _cfg.blocks.empty() )
            return;

        if ( ! isAcyclic(_cfg) )
            _emitter.emit(diag::ControlFlowCycle, id);
        _idom = immediateDominators(_cfg.successors, 0);
    }

    void _endBody() {
        _in_body = false;
        _cfg = {};
        _idom.clear();
    }

    void _verifyRegion(FunctionId id, RegionId region_id, const Function& fn, InstId owner) {
        if ( ! _active_regions.insert(region_id.index).second ) {
            _emitter.emit(diag::InvalidStructuredRegion, owner.isSet() ? owner : InstId{});
            return;
        }
        if ( ! _owned_regions.insert(region_id.index).second )
            _emitter.emit(diag::InvalidStructuredRegion, owner.isSet() ? owner : InstId{});
        const auto& region = _package.region(region_id);
        bool multi_block_body = ! owner.isSet() && fn.kind != FunctionKind::Parser;
        if ( multi_block_body ? region.blocks.empty() : region.blocks.size() != 1 )
            _emitter.emit(diag::RegionBlockCountMismatch, id, region.blocks.size());

        for ( auto block_id : region.blocks ) {
            if ( ! _package.isValid(block_id) ) {
                _emitter.emit(diag::InvalidBlockId, id);
                continue;
            }

            _verifyBlock(id, block_id, fn, owner);
        }
        _active_regions.erase(region_id.index);
    }

    // Catches orphaned or double-listed decls, in case verifyTypeDecl() misses it
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
    // Function kind/signature/parser-unit consistency.
    void _verifyFunctionKind(FunctionId id, const Function& fn) {
        if ( fn.kind != FunctionKind::Parser ) {
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

    void _verifyBlock(FunctionId function_id, BlockId block_id, const Function& fn, InstId owner) {
        const auto& block = _package.block(block_id);
        if ( block.insts.empty() ) {
            _emitter.emit(diag::EmptyBlock, block_id);
            return;
        }

        std::unordered_set<uint32_t> defined;
        std::unordered_set<uint32_t> bounded_states;
        std::unordered_set<uint32_t> bounded_tuples;

        for ( size_t i = 0; i < block.insts.size(); ++i ) {
            auto inst_id = block.insts[i];
            if ( ! _package.isValid(inst_id) ) {
                _emitter.emit(diag::InvalidInstructionId, block_id, i);
                continue;
            }

            _verifyInst(function_id, inst_id, block_id, i == block.insts.size() - 1, defined, fn.result_type);
            defined.insert(inst_id.index);

            const auto& inst = _package.inst(inst_id);
            if ( inst.opcode == Opcode::RegionArgument && owner.isSet() &&
                 std::get_if<ArgumentPayload>(&inst.payload) && std::get<ArgumentPayload>(inst.payload).index == 0 )
                bounded_states.insert(inst_id.index);
            else if ( inst.opcode == Opcode::EnterBound )
                bounded_states.insert(inst_id.index);
            else if ( inst.opcode == Opcode::ReadInteger || inst.opcode == Opcode::ReadBytes ||
                      inst.opcode == Opcode::ParseSubunit ) {
                if ( ! inst.args.empty() && bounded_states.contains(inst.args[0].index) )
                    bounded_tuples.insert(inst_id.index);
            }
            else if ( inst.opcode == Opcode::TupleGet && ! inst.args.empty() &&
                      std::get_if<TupleGetPayload>(&inst.payload) &&
                      std::get<TupleGetPayload>(inst.payload).index == 0 &&
                      bounded_tuples.contains(inst.args[0].index) )
                bounded_states.insert(inst_id.index);
            if ( inst.opcode == Opcode::LeaveBound &&
                 (inst.args.empty() || ! bounded_states.contains(inst.args[0].index)) )
                _emitter.emit(diag::InvalidParserOperation, inst_id);
            if ( inst.opcode == Opcode::RepeatToBound ) {
                if ( inst.args.empty() || ! bounded_states.contains(inst.args[0].index) )
                    _emitter.emit(diag::RepeatRequiresBound, inst_id);
                else
                    bounded_tuples.insert(inst_id.index);
                if ( inst.regions.size() != 1 || ! _package.isValid(inst.regions[0]) )
                    _emitter.emit(diag::InvalidStructuredRegion, inst_id);
                else
                    _verifyRegion(function_id, inst.regions[0], fn, inst_id);
            }
            else if ( ! inst.regions.empty() )
                _emitter.emit(diag::InvalidStructuredRegion, inst_id);
        }

        if ( owner.isSet() )
            _verifyRegionSignature(block_id, owner, bounded_states);
        else {
            // Only the entry block may start with arguments; ordinary functions' other blocks hold none.
            bool entry = block_id == _package.region(fn.root_region).blocks.front();
            if ( entry )
                _verifyArgumentPrefix(function_id, block_id, fn);
            for ( auto inst_id : block.insts ) {
                if ( ! _package.isValid(inst_id) )
                    continue;
                const auto& inst = _package.inst(inst_id);
                if ( inst.opcode == Opcode::RegionArgument )
                    _emitter.emit(diag::InvalidRegionArgument, inst_id);
                else if ( inst.opcode == Opcode::Yield )
                    _emitter.emit(diag::InvalidYield, inst_id);
                else if ( inst.opcode == Opcode::Argument && ! entry )
                    _emitter.emit(diag::ArgumentNotLeading, inst_id);
            }
        }
        // An ordinary function's body checks parser-state affinity across all of its blocks at once.
        if ( owner.isSet() || fn.kind == FunctionKind::Parser )
            _verifyParserStateAffinity(function_id, block_id);
        if ( ! owner.isSet() )
            _verifyUnitStateAffinity(function_id, block_id, fn);
    }

    void _verifyRegionSignature(BlockId block_id, InstId owner_id, const std::unordered_set<uint32_t>& bounded_states) {
        const auto& owner = _package.inst(owner_id);
        const auto& block = _package.block(block_id);
        if ( block.insts.size() < owner.args.size() + 1 ) {
            _emitter.emit(diag::InvalidStructuredRegion, owner_id);
            return;
        }

        for ( size_t i = 0; i < owner.args.size(); ++i ) {
            auto id = block.insts[i];
            if ( ! _package.isValid(id) || ! _package.isValid(owner.args[i]) )
                continue;
            const auto& arg = _package.inst(id);
            const auto* payload = std::get_if<ArgumentPayload>(&arg.payload);
            if ( arg.opcode != Opcode::RegionArgument || ! payload || payload->index != i ||
                 arg.result_type != _package.inst(owner.args[i]).result_type )
                _emitter.emit(diag::InvalidRegionArgument, id);
        }

        for ( size_t i = owner.args.size(); i < block.insts.size(); ++i ) {
            auto id = block.insts[i];
            if ( _package.isValid(id) && _package.inst(id).opcode == Opcode::RegionArgument )
                _emitter.emit(diag::InvalidRegionArgument, id);
        }

        auto terminator = block.insts.back();
        if ( ! _package.isValid(terminator) )
            return;
        const auto& yielded = _package.inst(terminator);
        if ( yielded.opcode != Opcode::Yield || yielded.args.size() != owner.args.size() ) {
            _emitter.emit(diag::InvalidYield, terminator);
            return;
        }
        for ( size_t i = 0; i < yielded.args.size(); ++i )
            if ( _package.isValid(yielded.args[i]) && _package.isValid(owner.args[i]) &&
                 _package.inst(yielded.args[i]).result_type != _package.inst(owner.args[i]).result_type )
                _emitter.emit(diag::InvalidYield, terminator);

        // The owner's result is treated as bounded, so the body must yield a state that still carries the bound.
        if ( ! yielded.args.empty() && _package.isValid(yielded.args[0]) &&
             ! bounded_states.contains(yielded.args[0].index) )
            _emitter.emit(diag::InvalidYield, terminator);
    }

    // Every `core.argument` in the entry block appears before any non-argument
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

    // Parser-state affinity. This only applies to the parser state, or tuples
    // which use said parser state. Primarily ensures each `parser.state` value only reaches one `OperandRole::Consume`.
    void _verifyParserStateAffinity(FunctionId /* function_id */, BlockId block_id) {
        const auto& block = _package.block(block_id);

        std::unordered_map<uint32_t, InstId> consumed_by;
        std::unordered_map<uint64_t, InstId> projected_by;

        for ( auto inst_id : block.insts ) {
            if ( ! _package.isValid(inst_id) )
                continue;

            const auto& inst = _package.inst(inst_id);

            // Ensure affine elements only projected by core.tuple_get at
            // most once.
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

            const auto* schema = schemaFor(inst.opcode);
            if ( ! schema )
                continue;

            for ( size_t a = 0; a < inst.args.size() && ! schema->operand_roles.empty(); ++a ) {
                if ( schema->operand_roles[std::min(a, schema->operand_roles.size() - 1)] != OperandRole::Consume )
                    continue;

                auto arg = inst.args[a];
                if ( ! _package.isValid(arg) )
                    continue;

                auto result_type = _package.inst(arg).result_type;
                if ( typeDiscipline(_package, result_type) != ValueDiscipline::Affine )
                    continue;

                auto [it, inserted] = consumed_by.try_emplace(arg.index, inst_id);
                if ( ! inserted )
                    _emitter.emit(diag::ParserStateReused, inst_id);
            }
        }
    }

    // Tracks each unit value's publication chain from `unit.create` through
    // `unit.publish_field` to `parser.finish`, as a direct per-function scan. Straight-line
    // affinity checking is sufficient here; a general dataflow framework is deferred.
    void _verifyUnitStateAffinity(FunctionId /* function_id */, BlockId block_id, const Function& fn) {
        const auto& block = _package.block(block_id);

        // Maps a unit.create's InstId to the current head of its publication chain, and the set
        // of field DeclIds published so far along that chain.
        struct Chain {
            InstId head;
            std::unordered_set<uint32_t> published;
        };
        std::vector<Chain> chains;

        auto find_chain = [&](InstId value) -> Chain* {
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

                auto* chain = find_chain(inst.args[0]);
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

                auto* chain = find_chain(inst.args[1]);
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

        const auto* schema = schemaFor(inst.opcode);
        if ( ! schema ) {
            _emitter.emit(diag::UnrecognizedOpcode, inst_id);
            return;
        }

        if ( schema->is_terminator && ! is_last_in_block )
            _emitter.emit(diag::TerminatorNotLast, inst_id);

        if ( ! schema->is_terminator && is_last_in_block )
            _emitter.emit(diag::MissingTerminator, block_id);

        // A void return has no operand; a value-returning one has exactly one, checked against its function below.
        bool void_return = inst.opcode == Opcode::Return && inst.args.empty();
        if ( ! void_return && (schema->variadic ? inst.args.size() < schema->operandCount() :
                                                  inst.args.size() != schema->operandCount()) )
            _emitter.emit(diag::OperandCountMismatch, inst_id, schema->operandCount(), inst.args.size());
        if ( void_return && function_result_type != _package.voidType() )
            _emitter.emit(diag::OperandCountMismatch, inst_id, schema->operandCount(), 0);

        if ( ! payloadMatchesKind(inst.payload, schema->payload_kind) ) {
            if ( schema->payload_kind == PayloadKind::None )
                _emitter.emit(diag::UnexpectedPayload, inst_id);
            else
                _emitter.emit(diag::MissingPayload, inst_id);
        }

        // Opcodes without operand type constraints (such as calls) still need their operands checked for validity,
        // block membership, and definition order.
        for ( size_t a = 0; a < inst.args.size(); ++a ) {
            const TypeConstraint* constraint =
                schema->operand_types.empty() ? nullptr :
                                                &schema->operand_types[std::min(a, schema->operand_types.size() - 1)];
            _verifyOperand(function_id, inst_id, block_id, constraint, a, inst.args[a], defined, function_result_type);
        }

        _verifyResultType(inst_id, inst, *schema);
        _verifyOpcodeSpecific(function_id, inst_id, inst);
    }

    // Result/operand construction that depends on payload content or on
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

            case Opcode::Call: {
                const auto* payload = std::get_if<FunctionPayload>(&inst.payload);
                if ( ! payload )
                    return;

                if ( ! _package.isValid(payload->function) ) {
                    _emitter.emit(diag::CallInvalidPayload, inst_id);
                    return;
                }

                const auto& callee = _package.function(payload->function);
                if ( callee.kind != FunctionKind::Normal )
                    _emitter.emit(diag::CallTargetNotNormal, inst_id);

                if ( inst.args.size() != callee.parameters.size() )
                    _emitter.emit(diag::CallArgumentCountMismatch, inst_id, callee.parameters.size(), inst.args.size());
                else {
                    for ( size_t a = 0; a < inst.args.size(); ++a ) {
                        if ( _package.isValid(inst.args[a]) &&
                             _package.inst(inst.args[a]).result_type != callee.parameters[a] )
                            _emitter.emit(diag::CallArgumentTypeMismatch, inst_id, a);
                    }
                }

                if ( inst.result_type != callee.result_type )
                    _emitter.emit(diag::CallResultTypeMismatch, inst_id);
                return;
            }

            case Opcode::Branch: {
                const auto* payload = std::get_if<BranchPayload>(&inst.payload);
                if ( ! payload )
                    return;

                _verifySuccessor(inst_id, inst, payload->then_block);
                _verifySuccessor(inst_id, inst, payload->else_block);
                return;
            }

            case Opcode::Jump: {
                const auto* payload = std::get_if<JumpPayload>(&inst.payload);
                if ( ! payload )
                    return;

                _verifySuccessor(inst_id, inst, payload->target);
                return;
            }

            case Opcode::Equal: {
                if ( inst.args.size() != 2 || ! _package.isValid(inst.args[0]) || ! _package.isValid(inst.args[1]) )
                    return;

                auto lhs = _package.inst(inst.args[0]).result_type;
                auto rhs = _package.inst(inst.args[1]).result_type;
                if ( lhs != rhs || ! _package.isValid(lhs) || ! _isComparable(_package.type(lhs).kind) )
                    _emitter.emit(diag::EqualOperandTypeMismatch, inst_id);
                return;
            }

            case Opcode::LocalPlace: {
                if ( inst.args.empty() || ! _package.isValid(inst.args[0]) )
                    return;

                // The place takes ownership of its initial value, which is affine for a vector.
                auto initial = _package.inst(inst.args[0]).result_type;
                if ( ! _package.isValid(initial) || initial == _package.voidType() ) {
                    _emitter.emit(diag::LocalPlaceInvalidInitial, inst_id);
                    return;
                }

                if ( ! _package.isValid(inst.result_type) || _package.type(inst.result_type).kind != TypeKind::Place ||
                     _package.type(inst.result_type).type_arguments != std::vector<TypeId>{initial} )
                    _emitter.emit(diag::LocalPlaceResultTypeMismatch, inst_id);
                return;
            }

            case Opcode::Load: {
                if ( inst.args.empty() || ! _package.isValid(inst.args[0]) )
                    return;

                auto place = _package.inst(inst.args[0]).result_type;
                if ( ! _package.isValid(place) || _package.type(place).kind != TypeKind::Place ) {
                    _emitter.emit(diag::PlaceOperandMismatch, inst_id, "core.load");
                    return;
                }

                if ( inst.result_type != _package.type(place).type_arguments[0] )
                    _emitter.emit(diag::LoadResultTypeMismatch, inst_id);
                else if ( _isNonCopyableOpaque(inst.result_type) )
                    _emitter.emit(diag::OpaqueLoadRequiresCopyable, inst_id);
                return;
            }

            case Opcode::Tuple: {
                if ( ! _package.isValid(inst.result_type) || _package.type(inst.result_type).kind != TypeKind::Tuple ) {
                    _emitter.emit(diag::TupleResultTypeMismatch, inst_id);
                    return;
                }

                const auto& elements = _package.type(inst.result_type).type_arguments;
                if ( elements.size() != inst.args.size() ) {
                    _emitter.emit(diag::TupleResultTypeMismatch, inst_id);
                    return;
                }

                for ( size_t a = 0; a < inst.args.size(); ++a )
                    if ( _package.isValid(inst.args[a]) && _package.inst(inst.args[a]).result_type != elements[a] )
                        _emitter.emit(diag::TupleResultTypeMismatch, inst_id);
                return;
            }

            case Opcode::FieldPlace: {
                const auto* payload = std::get_if<FieldPayload>(&inst.payload);
                if ( ! payload )
                    return;

                if ( ! _package.isValid(payload->field) ) {
                    _emitter.emit(diag::FieldPlaceInvalidPayload, inst_id);
                    return;
                }

                const auto& field = _package.declaration(payload->field);
                if ( inst.args.empty() || ! _package.isValid(inst.args[0]) )
                    return;

                auto unit = _package.inst(inst.args[0]).result_type;
                if ( ! _package.isValid(unit) || _package.type(unit).kind != TypeKind::Unit ||
                     _package.type(unit).declaration != field.owner )
                    _emitter.emit(diag::FieldPlaceUnitMismatch, inst_id);

                if ( ! _package.isValid(inst.result_type) || _package.type(inst.result_type).kind != TypeKind::Place ||
                     _package.type(inst.result_type).type_arguments != std::vector<TypeId>{field.type} )
                    _emitter.emit(diag::FieldPlaceResultTypeMismatch, inst_id);
                return;
            }

            case Opcode::InvokeHook: {
                const auto* payload = std::get_if<FunctionPayload>(&inst.payload);
                if ( ! payload )
                    return;

                if ( ! _package.isValid(payload->function) ) {
                    _emitter.emit(diag::InvokeHookInvalidPayload, inst_id);
                    return;
                }

                const auto& hook = _package.function(payload->function);
                if ( hook.kind != FunctionKind::Hook || hook.parameters.size() != 1 || inst.args.size() != 1 ||
                     ! _package.isValid(inst.args[0]) ||
                     _package.inst(inst.args[0]).result_type != hook.parameters[0] ||
                     hook.result_type != _package.voidType() || inst.result_type != _package.voidType() )
                    _emitter.emit(diag::InvokeHookOperandMismatch, inst_id);
                return;
            }

            case Opcode::GlobalPlace: {
                const auto* payload = std::get_if<GlobalPayload>(&inst.payload);
                if ( ! payload )
                    return;

                if ( ! _package.isValid(payload->global) ) {
                    _emitter.emit(diag::GlobalPlaceInvalidPayload, inst_id);
                    return;
                }

                const auto& global = _package.global(payload->global);
                if ( ! _package.isValid(inst.result_type) || _package.type(inst.result_type).kind != TypeKind::Place ||
                     _package.type(inst.result_type).type_arguments != std::vector<TypeId>{global.type} )
                    _emitter.emit(diag::GlobalPlaceResultTypeMismatch, inst_id);
                return;
            }

            case Opcode::Store: {
                if ( inst.args.size() != 2 || ! _package.isValid(inst.args[0]) || ! _package.isValid(inst.args[1]) )
                    return;

                auto place = _package.inst(inst.args[0]).result_type;
                if ( ! _package.isValid(place) || _package.type(place).kind != TypeKind::Place ) {
                    _emitter.emit(diag::PlaceOperandMismatch, inst_id, "core.store");
                    return;
                }

                if ( _package.inst(inst.args[1]).result_type != _package.type(place).type_arguments[0] )
                    _emitter.emit(diag::StoreValueTypeMismatch, inst_id);
                return;
            }

            case Opcode::OpaqueOp: {
                const auto* payload = std::get_if<ForeignFunctionPayload>(&inst.payload);
                if ( ! payload )
                    return;

                if ( ! _package.isValid(payload->function) ) {
                    _emitter.emit(diag::OpaqueOpInvalidPayload, inst_id);
                    return;
                }

                const auto& fn = _package.foreignFunction(payload->function);
                if ( inst.args.size() != fn.parameters.size() )
                    _emitter.emit(diag::OpaqueOpArgumentCountMismatch, inst_id, fn.parameters.size(), inst.args.size());
                else {
                    for ( size_t a = 0; a < inst.args.size(); ++a ) {
                        if ( ! _package.isValid(inst.args[a]) )
                            continue;

                        if ( ! _acceptsArgument(fn.parameters[a], _package.inst(inst.args[a]).result_type) )
                            _emitter.emit(diag::OpaqueOpArgumentTypeMismatch, inst_id, a);
                    }
                }

                if ( inst.result_type != fn.result_type )
                    _emitter.emit(diag::OpaqueOpResultTypeMismatch, inst_id);
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

                if ( (payload->width != 8 && payload->width != 64) || payload->signedness != Signedness::Unsigned ||
                     payload->byte_order != ByteOrder::Network )
                    _emitter.emit(diag::ReadIntegerUnsupportedPayload, inst_id);

                bool result_ok = _package.isValid(inst.result_type);
                if ( result_ok ) {
                    const auto& result = _package.type(inst.result_type);
                    result_ok = result.kind == TypeKind::Tuple && result.type_arguments.size() == 2 &&
                                _package.isValid(result.type_arguments[0]) &&
                                _package.type(result.type_arguments[0]).kind == TypeKind::ParserState &&
                                _package.isValid(result.type_arguments[1]) &&
                                _package.type(result.type_arguments[1]).kind ==
                                    (payload->width == 64 ? TypeKind::UInt64 : TypeKind::UInt8);
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

            case Opcode::VectorEmpty:
                if ( ! _package.isValid(inst.result_type) || _package.type(inst.result_type).kind != TypeKind::Vector )
                    _emitter.emit(diag::InvalidParserOperation, inst_id);
                return;

            case Opcode::VectorAppend:
                if ( inst.args.size() == 2 && _package.isValid(inst.args[0]) && _package.isValid(inst.args[1]) ) {
                    auto vector_type = _package.inst(inst.args[0]).result_type;
                    if ( ! _package.isValid(vector_type) || _package.type(vector_type).kind != TypeKind::Vector ||
                         _package.type(vector_type).type_arguments.size() != 1 ||
                         _package.type(vector_type).type_arguments[0] != _package.inst(inst.args[1]).result_type )
                        _emitter.emit(diag::InvalidParserOperation, inst_id);
                }
                return;

            case Opcode::EnterBound:
                if ( inst.args.size() == 2 && _package.isValid(inst.args[1]) ) {
                    auto length_type = _package.inst(inst.args[1]).result_type;
                    if ( ! _package.isValid(length_type) || (_package.type(length_type).kind != TypeKind::UInt8 &&
                                                             _package.type(length_type).kind != TypeKind::UInt64) )
                        _emitter.emit(diag::InvalidParserOperation, inst_id);
                }
                return;

            case Opcode::RepeatToBound: {
                if ( inst.args.empty() || ! _package.isValid(inst.args[0]) ||
                     ! _package.isValid(_package.inst(inst.args[0]).result_type) ||
                     _package.type(_package.inst(inst.args[0]).result_type).kind != TypeKind::ParserState ||
                     ! _package.isValid(inst.result_type) || _package.type(inst.result_type).kind != TypeKind::Tuple ||
                     _package.type(inst.result_type).type_arguments.size() != inst.args.size() ) {
                    _emitter.emit(diag::InvalidParserOperation, inst_id);
                    return;
                }
                for ( size_t i = 0; i < inst.args.size(); ++i )
                    if ( _package.isValid(inst.args[i]) &&
                         _package.type(inst.result_type).type_arguments[i] != _package.inst(inst.args[i]).result_type )
                        _emitter.emit(diag::InvalidParserOperation, inst_id);
                return;
            }

            case Opcode::ParseSubunit: {
                const auto* payload = std::get_if<FunctionPayload>(&inst.payload);
                if ( ! payload || ! _package.isValid(payload->function) ||
                     _package.function(payload->function).kind != FunctionKind::Parser ||
                     ! _package.isValid(inst.result_type) ) {
                    _emitter.emit(diag::InvalidParserOperation, inst_id);
                    return;
                }
                const auto& result = _package.type(inst.result_type);
                if ( result.kind != TypeKind::Tuple || result.type_arguments.size() != 2 ||
                     ! _package.isValid(result.type_arguments[0]) ||
                     _package.type(result.type_arguments[0]).kind != TypeKind::ParserState ||
                     result.type_arguments[1] != _package.function(payload->function).result_type )
                    _emitter.emit(diag::InvalidParserOperation, inst_id);
                return;
            }

            case Opcode::ReadBytes:
                if ( ! _package.isValid(inst.result_type) || _package.type(inst.result_type).kind != TypeKind::Tuple ||
                     _package.type(inst.result_type).type_arguments.size() != 2 ||
                     ! _package.isValid(_package.type(inst.result_type).type_arguments[0]) ||
                     ! _package.isValid(_package.type(inst.result_type).type_arguments[1]) ||
                     _package.type(_package.type(inst.result_type).type_arguments[0]).kind != TypeKind::ParserState ||
                     _package.type(_package.type(inst.result_type).type_arguments[1]).kind != TypeKind::Bytes )
                    _emitter.emit(diag::InvalidParserOperation, inst_id);
                return;

            default: return;
        }
    }

    // The types that `core.equal` compares.
    static bool _isComparable(TypeKind kind) {
        switch ( kind ) {
            case TypeKind::Int64:
            case TypeKind::UInt8:
            case TypeKind::UInt64:
            case TypeKind::Bool: return true;
            case TypeKind::Void:
            case TypeKind::Bytes:
            case TypeKind::ParserState:
            case TypeKind::Unit:
            case TypeKind::Tuple:
            case TypeKind::Vector:
            case TypeKind::Opaque:
            case TypeKind::Place:
            case TypeKind::String: return false;
        }

        return false;
    }

    // A branch or jump may only target blocks of the same ordinary function body.
    void _verifySuccessor(InstId inst_id, const Inst& inst, BlockId target) {
        if ( ! _in_body || ! _cfg.contains(inst.parent) ) {
            _emitter.emit(diag::ControlFlowOutsideFunctionBody, inst_id);
            return;
        }

        if ( ! _package.isValid(target) || ! _cfg.contains(target) )
            _emitter.emit(diag::InvalidSuccessor, inst_id);
    }

    // Whether a value defined in `def` is available in `use` by dominance. Blocks outside the body are never
    // available, and a use in a block unreachable from the entry is vacuously available.
    bool _availableFrom(BlockId def, BlockId use) const {
        if ( ! _in_body || ! _cfg.contains(def) || ! _cfg.contains(use) )
            return false;

        auto use_position = _cfg.position.at(use.index);
        if ( _idom[use_position] == NoPosition )
            return true;

        return dominates(_idom, _cfg.position.at(def.index), use_position);
    }

    // Affine values in an ordinary function may flow through several blocks, so each must be consumed at most once
    // along any path. Two consumers conflict unless neither can reach the other.
    void _verifyBodyAffinity() {
        const auto count = _cfg.blocks.size();
        std::vector<std::vector<bool>> reaches(count, std::vector<bool>(count, false));
        for ( size_t from = 0; from < count; ++from ) {
            std::vector<size_t> pending = _cfg.successors[from];
            while ( ! pending.empty() ) {
                auto next = pending.back();
                pending.pop_back();
                if ( reaches[from][next] )
                    continue;

                reaches[from][next] = true;
                pending.insert(pending.end(), _cfg.successors[next].begin(), _cfg.successors[next].end());
            }
        }

        struct Consumer {
            InstId inst;
            size_t block;
        };
        std::unordered_map<uint32_t, std::vector<Consumer>> consumed_values;
        std::unordered_map<uint64_t, std::vector<Consumer>> projected_slots;

        for ( size_t block = 0; block < count; ++block ) {
            for ( auto inst_id : _package.block(_cfg.blocks[block]).insts ) {
                if ( ! _package.isValid(inst_id) )
                    continue;

                const auto& inst = _package.inst(inst_id);
                if ( inst.opcode == Opcode::TupleGet ) {
                    const auto* payload = std::get_if<TupleGetPayload>(&inst.payload);
                    if ( ! payload || inst.args.empty() || ! _package.isValid(inst.args[0]) )
                        continue;

                    if ( typeDiscipline(_package, inst.result_type) == ValueDiscipline::Affine )
                        projected_slots[slotKey(inst.args[0], payload->index)].push_back(
                            {.inst = inst_id, .block = block});
                    continue;
                }

                const auto* schema = schemaFor(inst.opcode);
                if ( ! schema || schema->operand_roles.empty() )
                    continue;

                for ( size_t a = 0; a < inst.args.size(); ++a ) {
                    if ( schema->operand_roles[std::min(a, schema->operand_roles.size() - 1)] != OperandRole::Consume )
                        continue;

                    auto arg = inst.args[a];
                    if ( ! _package.isValid(arg) )
                        continue;

                    if ( typeDiscipline(_package, _package.inst(arg).result_type) == ValueDiscipline::Affine )
                        consumed_values[arg.index].push_back({.inst = inst_id, .block = block});
                }
            }
        }

        auto check = [&](const std::vector<Consumer>& consumers) {
            for ( size_t later = 1; later < consumers.size(); ++later ) {
                for ( size_t earlier = 0; earlier < later; ++earlier ) {
                    const auto& a = consumers[earlier];
                    const auto& b = consumers[later];
                    bool same_path = a.block == b.block || reaches[a.block][b.block] || reaches[b.block][a.block];
                    if ( same_path ) {
                        _emitter.emit(diag::ParserStateReused, b.inst);
                        break;
                    }
                }
            }
        };

        for ( const auto& [_, consumers] : consumed_values )
            check(consumers);
        for ( const auto& [_, consumers] : projected_slots )
            check(consumers);
    }

    void _verifyOperand(FunctionId function_id,
                        InstId user,
                        BlockId block_id,
                        const TypeConstraint* constraint,
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
            if ( ! _availableFrom(arg_inst.parent, block_id) ) {
                _emitter.emit(diag::OperandNotSameBlock, user, operand_index);
                return;
            }
        }
        else if ( ! defined.contains(arg.index) ) {
            _emitter.emit(diag::OperandUsedBeforeDefinition, user, operand_index);
            return;
        }

        if ( arg_inst.result_type == _package.voidType() )
            _emitter.emit(diag::VoidOperandUsed, user, operand_index);

        if ( constraint && ! _satisfies(*constraint, arg_inst.result_type, function_result_type) ) {
            if ( constraint->kind == TypeConstraintKind::SameAsFunctionResult )
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
    std::unordered_set<uint32_t> _active_regions;
    std::unordered_set<uint32_t> _owned_regions;
    // The CFG and dominator tree of the ordinary function body being verified, if any.
    bool _in_body = false;
    Cfg _cfg;
    std::vector<size_t> _idom;
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

    for ( size_t i = 0; i < package.foreignFunctions().size(); ++i ) {
        auto id = ForeignFunctionId{static_cast<uint32_t>(i)};
        verifier.verifyForeignFunction(id, package.foreignFunction(id));
    }

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

    for ( auto root : package.functionRoots() ) {
        if ( ! package.isValid(root) )
            emitter.emit(diag::InvalidFunctionRoot, noSite());
        else if ( package.function(root).kind != FunctionKind::Normal )
            emitter.emit(diag::FunctionRootNotNormal, root);
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
