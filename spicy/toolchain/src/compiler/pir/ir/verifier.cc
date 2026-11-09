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

// Kinda weird, just makes a unique key for tuple instruction + its index
// so we can check if this tuple instruction gets consumed multiple
// times from just a "key."
uint64_t slotKey(InstId tuple_inst, uint32_t index) { return (static_cast<uint64_t>(tuple_inst.index) << 32U) | index; }

class Verifier {
public:
    Verifier(const Package& package, std::vector<InternalError>& errors)
        : _package(package), _emitter(package, errors) {}

    void verifyType(TypeId id, const Type& type) {
        if ( type.kind == TypeKind::Unit ) {
            if ( ! _package.isValid(type.declaration) )
                _emitter.emit("type-missing-declaration", "unit type does not reference a valid type declaration", id);
        }
        else if ( type.kind == TypeKind::Opaque ) {
            if ( ! _package.isValid(type.declaration) ||
                 _package.typeDecl(type.declaration).kind != TypeDeclKind::Opaque )
                _emitter.emit("type-opaque-missing-declaration",
                              "opaque type does not reference an opaque type declaration",
                              id);
        }
        else if ( type.declaration.isSet() )
            _emitter.emit("type-unexpected-declaration", "only a unit type may carry a type declaration", id);

        if ( type.kind == TypeKind::Tuple || type.kind == TypeKind::Vector || type.kind == TypeKind::Set ) {
            if ( (type.kind == TypeKind::Vector || type.kind == TypeKind::Set) && type.type_arguments.size() != 1 )
                _emitter.emit("type-unexpected-type-arguments", "only a tuple type may carry type arguments", id);
            for ( size_t a = 0; a < type.type_arguments.size(); ++a ) {
                if ( ! _package.isValid(type.type_arguments[a]) )
                    _emitter.emit("type-invalid-type-argument",
                                  "tuple type argument %zu is not a valid type ID",
                                  id,
                                  a);
                else if ( _package.type(type.type_arguments[a]).kind == TypeKind::Place )
                    _emitter
                        .emit("place-escapes",
                              "a place may only be a parameter or an operand, not a function result, field, or element",
                              id);
            }
        }
        else if ( type.kind == TypeKind::Place ) {
            if ( type.type_arguments.size() != 1 || ! _package.isValid(type.type_arguments[0]) )
                _emitter.emit("place-missing-element",
                              "place type must carry exactly one valid element type argument",
                              id);
        }
        else if ( ! type.type_arguments.empty() )
            _emitter.emit("type-unexpected-type-arguments", "only a tuple type may carry type arguments", id);
    }

    void verifyTypeDecl(TypeDeclId id, const TypeDecl& decl) {
        _verifySpan(decl.span, id);

        if ( decl.kind == TypeDeclKind::Opaque ) {
            if ( ! decl.opaque )
                _emitter.emit("type-decl-opaque-info-mismatch",
                              "native binding information must be present exactly for opaque type declarations",
                              id);
            else if ( decl.opaque->cxx_name.empty() || ! decl.opaque->lifecycle )
                _emitter.emit("opaque-declaration-incomplete",
                              "opaque type declaration must name its native type and declare its lifecycle",
                              id);
        }
        else if ( decl.opaque )
            _emitter.emit("type-decl-opaque-info-mismatch",
                          "native binding information must be present exactly for opaque type declarations",
                          id);

        for ( auto field_id : decl.fields ) {
            if ( ! _package.isValid(field_id) ) {
                _emitter.emit("invalid-field-declaration-id", "unit declaration references an invalid field ID", id);
                continue;
            }

            const auto& field = _package.declaration(field_id);
            if ( field.owner != id )
                _emitter.emit("field-owner-mismatch",
                              "field's cached owner does not match the unit declaring it",
                              field_id);

            _verifySpan(field.span, field_id);

            if ( ! _package.isValid(field.type) )
                _emitter.emit("invalid-field-type", "field does not reference a valid type ID", field_id);
            else if ( _package.type(field.type).kind == TypeKind::Place )
                _emitter.emit("place-escapes",
                              "a place may only be a parameter or an operand, not a function result, field, or element",
                              field_id);
        }
    }

    void verifyForeignFunction(ForeignFunctionId id, const ForeignFunction& fn) {
        _verifySpan(fn.span, id);

        // A function has one implementation: a native symbol, or the target adapter.
        if ( fn.cxx_name.empty() == ! fn.target_provided )
            _emitter.emit("foreign-function-missing-binding",
                          "foreign function must either name its native symbol or be provided by the target",
                          id);

        if ( ! _package.isValid(fn.result_type) || typeDiscipline(_package, fn.result_type) == ValueDiscipline::Affine )
            _emitter.emit("foreign-function-invalid-result",
                          "foreign function result must be a valid type that a native call returns by value",
                          id);

        for ( size_t p = 0; p < fn.parameters.size(); ++p ) {
            const auto& parameter = fn.parameters[p];
            if ( parameter.argument != ForeignArgument::Value )
                continue;

            // A by-value parameter takes its argument, so affinity does not restrict it; only a void or missing type
            // does.
            if ( ! _package.isValid(parameter.type) || parameter.type == _package.voidType() )
                _emitter.emit("foreign-function-invalid-parameter",
                              "foreign function parameter %zu must be a valid type that a native call accepts by value",
                              id,
                              p);
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
            _emitter.emit("invalid-function-result-type", "function's result type is not a valid type ID", id);
        else if ( _package.type(fn.result_type).kind == TypeKind::Place )
            _emitter.emit("place-escapes",
                          "a place may only be a parameter or an operand, not a function result, field, or element",
                          id);

        if ( fn.kind == FunctionKind::Normal ) {
            for ( size_t p = 0; p < fn.parameters.size(); ++p )
                if ( ! _isValidParameter(fn.parameters[p]) )
                    _emitter.emit("normal-function-invalid-parameter",
                                  "parameter %zu of an ordinary function must have a valid type for its mode: a taken "
                                  "value is not a place, and a borrow is a place or an affine value",
                                  id,
                                  p);
        }

        _verifyFunctionKind(id, fn);

        if ( ! _package.isValid(fn.root_region) ) {
            _emitter.emit("invalid-root-region", "function's root region is not a valid region ID", id);
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

    // Whether a parameter's type suits its mode. A taken value is copyable, or a unit, vector, or set that the callee
    // owns. A borrow is the access to storage (a place) or to an affine object that the caller keeps; a parser state is
    // consumed by parser operations only, so it is never borrowed.
    bool _isValidParameter(const Parameter& parameter) const {
        if ( ! _package.isValid(parameter.type) || parameter.type == _package.voidType() )
            return false;

        const auto kind = _package.type(parameter.type).kind;
        const bool affine = typeDiscipline(_package, parameter.type) == ValueDiscipline::Affine;
        switch ( parameter.mode ) {
            case ParameterMode::Take:
                return kind != TypeKind::Place &&
                       (! affine || kind == TypeKind::Unit || kind == TypeKind::Vector || kind == TypeKind::Set);
            case ParameterMode::Borrow:
            case ParameterMode::BorrowMut:
                return kind == TypeKind::Place || (affine && kind != TypeKind::ParserState && kind != TypeKind::Tuple);
        }

        return false;
    }

    void _beginBody(FunctionId id, const Function& fn) {
        _cfg = buildCfg(_package, fn.root_region);
        _in_body = true;
        if ( _cfg.blocks.empty() )
            return;

        if ( ! isAcyclic(_cfg) )
            _emitter.emit("control-flow-cycle",
                          "function's control flow contains a cycle, which PIR does not support yet",
                          id);
        _idom = immediateDominators(_cfg.successors, 0);
    }

    void _endBody() {
        _in_body = false;
        _cfg = {};
        _idom.clear();
    }

    void _verifyRegion(FunctionId id, RegionId region_id, const Function& fn, InstId owner) {
        if ( ! _active_regions.insert(region_id.index).second ) {
            _emitter.emit("invalid-structured-region",
                          "structured parser operation must own exactly one valid body region",
                          owner.isSet() ? owner : InstId{});
            return;
        }
        if ( ! _owned_regions.insert(region_id.index).second )
            _emitter.emit("invalid-structured-region",
                          "structured parser operation must own exactly one valid body region",
                          owner.isSet() ? owner : InstId{});
        const auto& region = _package.region(region_id);
        bool multi_block_body = ! owner.isSet() && fn.kind != FunctionKind::Parser;
        if ( multi_block_body ? region.blocks.empty() : region.blocks.size() != 1 )
            _emitter.emit(
                "region-block-count-mismatch",
                "function's region must contain exactly one block (an ordinary function needs at least one), has %zu",
                id,
                region.blocks.size());

        for ( auto block_id : region.blocks ) {
            if ( ! _package.isValid(block_id) ) {
                _emitter.emit("invalid-block-id", "region references an invalid block ID", id);
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
                _emitter.emit("declaration-invalid-owner",
                              "declaration's owner is not a valid type declaration ID",
                              id);
                continue;
            }

            auto it = membership_count.find(id.index);
            auto count = it != membership_count.end() ? it->second : 0;

            if ( count == 0 )
                _emitter.emit("declaration-not-in-owner-membership",
                              "declaration does not appear in its owner's membership vector",
                              id);
            else if ( count > 1 )
                _emitter.emit("declaration-duplicate-owner-membership",
                              "declaration appears more than once in its owner's membership vector",
                              id);
        }
    }

    void verifyParserRoot(const ParserRoot& root) {
        if ( ! _package.isValid(root.unit) ) {
            _emitter.emit("invalid-parser-root-unit", "parser root references an invalid unit declaration", noSite());
            return;
        }

        if ( ! _package.isValid(root.function) ) {
            _emitter.emit("invalid-parser-root-function", "parser root references an invalid function", root.unit);
            return;
        }

        const auto& fn = _package.function(root.function);
        if ( fn.kind != FunctionKind::Parser ) {
            _emitter.emit("parser-root-function-kind-mismatch",
                          "parser root's function is not a parser function",
                          root.function);
            return;
        }

        if ( fn.parser_unit != root.unit )
            _emitter.emit("parser-root-unit-mismatch",
                          "parser root's unit does not match its function's parser unit",
                          root.function);

        if ( root.context.has_value() != (fn.parameters.size() == 2) )
            _emitter.emit("parser-root-context-mismatch",
                          "a parser root describes a context exactly when its function takes one, with a name for each "
                          "tuple element",
                          root.function);
        else if ( root.context && _package.isValid(fn.parameters[1].type) &&
                  _package.type(fn.parameters[1].type).kind == TypeKind::Place &&
                  _package.type(fn.parameters[1].type).type_arguments.size() == 1 ) {
            // Every element of the context's tuple has a name, and nothing else does.
            const auto& tuple = _package.type(_package.type(fn.parameters[1].type).type_arguments[0]);
            if ( tuple.kind == TypeKind::Tuple && tuple.type_arguments.size() != root.context->elements.size() )
                _emitter.emit("parser-root-context-mismatch",
                              "a parser root describes a context exactly when its function takes one, with a name for "
                              "each tuple element",
                              root.function);
        }
    }

private:
    // Function kind/signature/parser-unit consistency.
    void _verifyFunctionKind(FunctionId id, const Function& fn) {
        if ( fn.kind != FunctionKind::Parser ) {
            if ( fn.parser_unit.isSet() )
                _emitter.emit("normal-function-with-parser-unit",
                              "an ordinary function must not reference a parser unit",
                              id);
            return;
        }

        if ( ! _package.isValid(fn.parser_unit) ) {
            _emitter.emit("parser-function-missing-parser-unit",
                          "a parser function must reference a valid parser unit",
                          id);
            return;
        }

        if ( fn.parameters.empty() || fn.parameters.size() > 2 )
            _emitter
                .emit("parser-function-parameter-count-mismatch",
                      "a parser function must have a parser state and at most a context borrow as parameters, has %zu",
                      id,
                      fn.parameters.size());
        else if ( ! _package.isValid(fn.parameters[0].type) ||
                  _package.type(fn.parameters[0].type).kind != TypeKind::ParserState ||
                  fn.parameters[0].mode != ParameterMode::Take )
            _emitter.emit("parser-function-parameter-type-mismatch",
                          "a parser function's parameter must be parser.state",
                          id);
        else if ( fn.parameters.size() == 2 &&
                  (fn.parameters[1].mode != ParameterMode::BorrowMut || ! _package.isValid(fn.parameters[1].type) ||
                   _package.type(fn.parameters[1].type).kind != TypeKind::Place ||
                   _package.type(fn.parameters[1].type).type_arguments.size() != 1 ||
                   _package.type(_package.type(fn.parameters[1].type).type_arguments[0]).kind != TypeKind::Tuple) )
            _emitter
                .emit("parser-function-context-parameter-mismatch",
                      "a parser function's second parameter must be a writable borrow of a place that holds a tuple",
                      id);

        if ( _package.isValid(fn.result_type) ) {
            const auto& result = _package.type(fn.result_type);
            if ( result.kind != TypeKind::Unit || result.declaration != fn.parser_unit )
                _emitter.emit("parser-function-result-type-mismatch",
                              "a parser function's result type must be its parser unit's nominal type",
                              id);
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
            _emitter.emit("invalid-source-span-id", "reference to an invalid source span ID", site);
            return;
        }

        const auto& s = sources.span(span);
        if ( ! sources.isValid(s.file) )
            _emitter.emit("invalid-source-file-id", "source span references an invalid source file ID", site);

        if ( s.begin_line >= 0 && s.end_line >= 0 && s.begin_line == s.end_line && s.begin_column >= 0 &&
             s.end_column >= 0 && s.end_column < s.begin_column )
            _emitter.emit("malformed-source-span-range", "source span has a reversed %s range", site, "column");

        if ( s.begin_line >= 0 && s.end_line >= 0 && s.end_line < s.begin_line )
            _emitter.emit("malformed-source-span-range", "source span has a reversed %s range", site, "line");
    }

    void _verifyBlock(FunctionId function_id, BlockId block_id, const Function& fn, InstId owner) {
        const auto& block = _package.block(block_id);
        if ( block.insts.empty() ) {
            _emitter.emit("empty-block", "block has no instructions and therefore no terminator", block_id);
            return;
        }

        std::unordered_set<uint32_t> defined;
        std::unordered_set<uint32_t> bounded_states;
        std::unordered_set<uint32_t> bounded_tuples;

        for ( size_t i = 0; i < block.insts.size(); ++i ) {
            auto inst_id = block.insts[i];
            if ( ! _package.isValid(inst_id) ) {
                _emitter.emit("invalid-instruction-id", "instruction at position %zu has an invalid ID", block_id, i);
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
            else if ( inst.opcode == Opcode::ReleaseInput ) {
                // Releasing input keeps the position and bounds of the state it receives.
                if ( ! inst.args.empty() && bounded_states.contains(inst.args[0].index) )
                    bounded_states.insert(inst_id.index);
            }
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
                _emitter.emit("invalid-parser-operation",
                              "parser operation has inconsistent types, payload, or region signature",
                              inst_id);
            if ( inst.opcode == Opcode::RepeatToBound ) {
                if ( inst.args.empty() || ! bounded_states.contains(inst.args[0].index) )
                    _emitter.emit("repeat-requires-bound",
                                  "parser.repeat_to_bound requires an active byte bound on its input state",
                                  inst_id);
                else
                    bounded_tuples.insert(inst_id.index);
                if ( inst.regions.size() != 1 || ! _package.isValid(inst.regions[0]) )
                    _emitter.emit("invalid-structured-region",
                                  "structured parser operation must own exactly one valid body region",
                                  inst_id);
                else
                    _verifyRegion(function_id, inst.regions[0], fn, inst_id);
            }
            else if ( ! inst.regions.empty() )
                _emitter.emit("invalid-structured-region",
                              "structured parser operation must own exactly one valid body region",
                              inst_id);
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
                    _emitter.emit("invalid-region-argument",
                                  "region argument is not a leading argument with the expected type and index",
                                  inst_id);
                else if ( inst.opcode == Opcode::Yield )
                    _emitter.emit("invalid-yield", "region yield does not match its owner's carried values", inst_id);
                else if ( inst.opcode == Opcode::Argument && ! entry )
                    _emitter.emit("argument-not-leading",
                                  "core.argument must appear before any non-argument instruction in the entry block",
                                  inst_id);
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
            _emitter.emit("invalid-structured-region",
                          "structured parser operation must own exactly one valid body region",
                          owner_id);
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
                _emitter.emit("invalid-region-argument",
                              "region argument is not a leading argument with the expected type and index",
                              id);
        }

        for ( size_t i = owner.args.size(); i < block.insts.size(); ++i ) {
            auto id = block.insts[i];
            if ( _package.isValid(id) && _package.inst(id).opcode == Opcode::RegionArgument )
                _emitter.emit("invalid-region-argument",
                              "region argument is not a leading argument with the expected type and index",
                              id);
        }

        auto terminator = block.insts.back();
        if ( ! _package.isValid(terminator) )
            return;
        const auto& yielded = _package.inst(terminator);
        if ( yielded.opcode != Opcode::Yield || yielded.args.size() != owner.args.size() ) {
            _emitter.emit("invalid-yield", "region yield does not match its owner's carried values", terminator);
            return;
        }
        for ( size_t i = 0; i < yielded.args.size(); ++i )
            if ( _package.isValid(yielded.args[i]) && _package.isValid(owner.args[i]) &&
                 _package.inst(yielded.args[i]).result_type != _package.inst(owner.args[i]).result_type )
                _emitter.emit("invalid-yield", "region yield does not match its owner's carried values", terminator);

        // The owner's result is treated as bounded, so the body must yield a state that still carries the bound.
        if ( ! yielded.args.empty() && _package.isValid(yielded.args[0]) &&
             ! bounded_states.contains(yielded.args[0].index) )
            _emitter.emit("invalid-yield", "region yield does not match its owner's carried values", terminator);
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
                _emitter.emit("argument-not-leading",
                              "core.argument must appear before any non-argument instruction in the entry block",
                              inst_id);
                continue;
            }

            const auto* payload = std::get_if<ArgumentPayload>(&inst.payload);
            if ( ! payload )
                continue; // reported generically as a payload-shape mismatch already

            if ( payload->index >= fn.parameters.size() ) {
                _emitter.emit("argument-index-out-of-range",
                              "core.argument index %u is out of range for %zu parameter(s)",
                              inst_id,
                              payload->index,
                              fn.parameters.size());
                continue;
            }

            if ( ! seen_indices.insert(payload->index).second )
                _emitter.emit("argument-index-duplicate",
                              "core.argument index %u is bound more than once",
                              inst_id,
                              payload->index);
        }

        for ( size_t i = 0; i < fn.parameters.size(); ++i )
            if ( ! seen_indices.contains(static_cast<uint32_t>(i)) )
                _emitter.emit("argument-index-missing",
                              "function parameter %zu has no core.argument binding it",
                              function_id,
                              i);
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
                    _emitter.emit("parser-state-reused",
                                  "parser state value is consumed by more than one state-transforming operation",
                                  inst_id);
                continue;
            }

            if ( ! schemaFor(inst.opcode) )
                continue;

            // The operands are checked against the consumptions that came before them, so a value that this
            // instruction consumes is not reported against itself.
            for ( size_t a = 0; a < inst.args.size(); ++a ) {
                auto arg = inst.args[a];
                if ( ! _package.isValid(arg) )
                    continue;

                if ( typeDiscipline(_package, _package.inst(arg).result_type) != ValueDiscipline::Affine ) {
                    // A place derived from a unit is an access to that unit.
                    auto owner = _derivedOwner(arg);
                    if ( owner.isSet() && consumed_by.contains(owner.index) )
                        _emitter.emit("use-after-consume",
                                      "operand %zu uses an affine value after an operation consumed it",
                                      inst_id,
                                      a);
                    continue;
                }

                auto role = operandRole(_package, inst, a);
                if ( role == OperandRole::Borrow && consumed_by.contains(arg.index) )
                    _emitter.emit("use-after-consume",
                                  "operand %zu uses an affine value after an operation consumed it",
                                  inst_id,
                                  a);
            }

            for ( size_t a = 0; a < inst.args.size(); ++a ) {
                if ( operandRole(_package, inst, a) != OperandRole::Consume )
                    continue;

                auto arg = inst.args[a];
                if ( ! _package.isValid(arg) )
                    continue;

                auto result_type = _package.inst(arg).result_type;
                if ( typeDiscipline(_package, result_type) != ValueDiscipline::Affine )
                    continue;

                auto [it, inserted] = consumed_by.try_emplace(arg.index, inst_id);
                if ( ! inserted )
                    _emitter.emit("parser-state-reused",
                                  "parser state value is consumed by more than one state-transforming operation",
                                  inst_id);
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
                    _emitter.emit("unit-state-stale-or-unknown-operand",
                                  "operand does not reference a live unit-state value created earlier in this function",
                                  inst_id);
                    continue;
                }

                const auto* payload = std::get_if<FieldPayload>(&inst.payload);
                if ( payload && _package.isValid(payload->field) ) {
                    if ( ! chain->published.insert(payload->field.index).second )
                        _emitter.emit("duplicate-field-publication", "field is published more than once", inst_id);
                }

                chain->head = inst_id;
                continue;
            }

            if ( inst.opcode == Opcode::Finish ) {
                if ( inst.args.size() < 2 || ! _package.isValid(inst.args[1]) )
                    continue;

                auto* chain = find_chain(inst.args[1]);
                if ( ! chain ) {
                    _emitter.emit("unit-state-stale-or-unknown-operand",
                                  "operand does not reference a live unit-state value created earlier in this function",
                                  inst_id);
                    continue;
                }

                if ( _package.isValid(fn.parser_unit) ) {
                    for ( auto field_id : _package.typeDecl(fn.parser_unit).fields )
                        if ( ! chain->published.contains(field_id.index) )
                            _emitter.emit("missing-field-publication",
                                          "parser.finish completes a unit that has not published all of its fields",
                                          inst_id);
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
            _emitter.emit("cached-parent-mismatch",
                          "instruction's cached parent block (%%%u) does not match its containing block (%%%u)",
                          inst_id,
                          inst.parent.index,
                          block_id.index);

        const auto* schema = schemaFor(inst.opcode);
        if ( ! schema ) {
            _emitter.emit("unrecognized-opcode", "unrecognized opcode", inst_id);
            return;
        }

        if ( schema->is_terminator && ! is_last_in_block )
            _emitter.emit("terminator-not-last", "terminator is not the last instruction in its block", inst_id);

        if ( ! schema->is_terminator && is_last_in_block )
            _emitter.emit("missing-terminator", "block does not end in a terminator", block_id);

        // A void return has no operand; a value-returning one has exactly one, checked against its function below.
        bool void_return = inst.opcode == Opcode::Return && inst.args.empty();
        if ( ! void_return && (schema->variadic ? inst.args.size() < schema->operandCount() :
                                                  inst.args.size() != schema->operandCount()) )
            _emitter.emit("operand-count-mismatch",
                          "expected %zu operand(s), got %zu",
                          inst_id,
                          schema->operandCount(),
                          inst.args.size());
        if ( void_return && function_result_type != _package.voidType() )
            _emitter.emit("operand-count-mismatch",
                          "expected %zu operand(s), got %zu",
                          inst_id,
                          schema->operandCount(),
                          0);

        if ( ! payloadMatchesKind(inst.payload, schema->payload_kind) ) {
            if ( schema->payload_kind == PayloadKind::None )
                _emitter.emit("unexpected-payload", "unexpected integer payload", inst_id);
            else
                _emitter.emit("missing-payload", "missing required integer payload", inst_id);
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
        _verifyBorrows(function_id, inst_id, inst);
    }

    // The unit value that a place was derived from by `unit.field_place`, if `id` is such a place. Using the place is
    // an access to that unit value, so it ends when that value's ownership transfers. A unit value read out of
    // storage is its own owner here: consuming it ends the access, whatever storage it came from.
    InstId _derivedOwner(InstId id) const {
        if ( ! _package.isValid(id) )
            return {};

        const auto& inst = _package.inst(id);
        if ( inst.opcode != Opcode::FieldPlace || inst.args.empty() || ! _package.isValid(inst.args[0]) )
            return {};

        return inst.args[0];
    }

    // What a value is allowed to do because of where it comes from. A value derived from a borrowed parameter belongs
    // to the caller: it cannot be consumed or returned, and it can be written only if the borrow allows writing.
    struct Origin {
        bool borrowed = false;
        bool writable = true;
    };

    Origin _origin(FunctionId function, InstId id, unsigned depth = 0) const {
        if ( depth > 64 || ! _package.isValid(id) || ! _package.isValid(function) )
            return {};

        const auto& inst = _package.inst(id);
        switch ( inst.opcode ) {
            case Opcode::Argument: {
                const auto* payload = std::get_if<ArgumentPayload>(&inst.payload);
                const auto& parameters = _package.function(function).parameters;
                if ( ! payload || payload->index >= parameters.size() )
                    return {};

                switch ( parameters[payload->index].mode ) {
                    case ParameterMode::Take: return {};
                    case ParameterMode::Borrow: return {.borrowed = true, .writable = false};
                    case ParameterMode::BorrowMut: return {.borrowed = true, .writable = true};
                }

                return {};
            }

            // A field of a borrowed unit is reached through the same borrow.
            case Opcode::FieldPlace: return inst.args.empty() ? Origin{} : _origin(function, inst.args[0], depth + 1);

            // Reading a copyable value yields an independent value. An affine value read from a place moves out of it,
            // which only storage the callee may write allows.
            case Opcode::Load: {
                if ( inst.args.empty() || typeDiscipline(_package, inst.result_type) != ValueDiscipline::Affine )
                    return {};

                auto place = _origin(function, inst.args[0], depth + 1);
                return place.borrowed && ! place.writable ? place : Origin{};
            }

            default: return {};
        }
    }

    // Ownership and access rules that follow from where operands come from. They hold for any function, whatever it
    // is called.
    void _verifyBorrows(FunctionId function, InstId inst_id, const Inst& inst) {
        auto denies_write = [&](size_t operand) {
            return operand < inst.args.size() && [&] {
                auto origin = _origin(function, inst.args[operand]);
                return origin.borrowed && ! origin.writable;
            }();
        };

        for ( size_t a = 0; a < inst.args.size(); ++a ) {
            if ( ! _package.isValid(inst.args[a]) )
                continue;

            auto type = _package.inst(inst.args[a]).result_type;
            if ( operandRole(_package, inst, a) == OperandRole::Consume &&
                 typeDiscipline(_package, type) == ValueDiscipline::Affine && _origin(function, inst.args[a]).borrowed )
                _emitter.emit("borrowed-value-consumed",
                              "operand %zu consumes a value that was only borrowed; its owner is the caller",
                              inst_id,
                              a);
        }

        switch ( inst.opcode ) {
            case Opcode::Return:
                if ( ! inst.args.empty() && _package.isValid(inst.args[0]) &&
                     _origin(function, inst.args[0]).borrowed &&
                     typeDiscipline(_package, _package.inst(inst.args[0]).result_type) == ValueDiscipline::Affine )
                    _emitter.emit("borrow-escapes",
                                  "a borrowed value cannot be returned, because the borrow ends with the call",
                                  inst_id);
                return;

            case Opcode::Store:
                if ( denies_write(0) )
                    _emitter.emit("borrow-write-denied",
                                  "operand %zu requires write access, but it derives from a read-only borrow",
                                  inst_id,
                                  size_t{0});
                return;

            case Opcode::Call: {
                const auto* payload = std::get_if<FunctionPayload>(&inst.payload);
                if ( ! payload || ! _package.isValid(payload->function) )
                    return;

                const auto& callee = _package.function(payload->function);
                for ( size_t a = 0; a < inst.args.size() && a < callee.parameters.size(); ++a )
                    if ( callee.parameters[a].mode == ParameterMode::BorrowMut && denies_write(a) )
                        _emitter.emit("borrow-write-denied",
                                      "operand %zu requires write access, but it derives from a read-only borrow",
                                      inst_id,
                                      a);
                return;
            }

            case Opcode::OpaqueOp: {
                // A native `inout` parameter writes through the place it receives.
                const auto* payload = std::get_if<ForeignFunctionPayload>(&inst.payload);
                if ( ! payload || ! _package.isValid(payload->function) )
                    return;

                const auto& foreign = _package.foreignFunction(payload->function);
                for ( size_t a = 0; a < inst.args.size() && a < foreign.parameters.size(); ++a ) {
                    const auto& parameter = foreign.parameters[a];
                    if ( parameter.argument == ForeignArgument::Value && _package.isValid(parameter.type) &&
                         _package.type(parameter.type).kind == TypeKind::Place && denies_write(a) )
                        _emitter.emit("borrow-write-denied",
                                      "operand %zu requires write access, but it derives from a read-only borrow",
                                      inst_id,
                                      a);
                }
                return;
            }

            default: return;
        }
    }

    // Result/operand construction that depends on payload content or on
    // the operand's actual structural type, which a static `TypeConstraint` cannot express.
    void _verifyOpcodeSpecific(FunctionId function_id, InstId inst_id, const Inst& inst) {
        switch ( inst.opcode ) {
            case Opcode::Finish: {
                if ( _package.isValid(function_id) && _package.function(function_id).kind != FunctionKind::Parser )
                    _emitter.emit("finish-in-normal-function",
                                  "parser.finish may only terminate a parser function",
                                  inst_id);
                return;
            }

            case Opcode::Argument: {
                const auto* payload = std::get_if<ArgumentPayload>(&inst.payload);
                if ( ! payload || ! _package.isValid(function_id) )
                    return;

                const auto& fn = _package.function(function_id);
                if ( payload->index < fn.parameters.size() && inst.result_type != fn.parameters[payload->index].type )
                    _emitter.emit("argument-result-type-mismatch",
                                  "core.argument's result type does not match its function's parameter type",
                                  inst_id);
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
                    _emitter.emit("tuple-get-operand-not-tuple",
                                  "core.tuple_get's operand is not a tuple type",
                                  inst_id);
                    return;
                }

                if ( payload->index >= operand_type.type_arguments.size() ) {
                    _emitter.emit("tuple-get-index-out-of-range",
                                  "core.tuple_get index %u is out of range for a %zu-element tuple",
                                  inst_id,
                                  payload->index,
                                  operand_type.type_arguments.size());
                    return;
                }

                if ( inst.result_type != operand_type.type_arguments[payload->index] )
                    _emitter.emit("tuple-get-result-type-mismatch",
                                  "core.tuple_get's result type does not match the selected tuple element",
                                  inst_id);
                return;
            }

            case Opcode::Call: {
                const auto* payload = std::get_if<FunctionPayload>(&inst.payload);
                if ( ! payload )
                    return;

                if ( ! _package.isValid(payload->function) ) {
                    _emitter.emit("call-invalid-payload",
                                  "core.call's payload does not reference a valid function",
                                  inst_id);
                    return;
                }

                const auto& callee = _package.function(payload->function);
                if ( callee.kind != FunctionKind::Normal )
                    _emitter.emit("call-target-not-normal", "core.call must target an ordinary function", inst_id);

                if ( inst.args.size() != callee.parameters.size() )
                    _emitter.emit("call-argument-count-mismatch",
                                  "core.call passes %zu argument(s) to a function with %zu parameter(s)",
                                  inst_id,
                                  callee.parameters.size(),
                                  inst.args.size());
                else {
                    for ( size_t a = 0; a < inst.args.size(); ++a ) {
                        if ( _package.isValid(inst.args[a]) &&
                             _package.inst(inst.args[a]).result_type != callee.parameters[a].type )
                            _emitter.emit("call-argument-type-mismatch",
                                          "core.call argument %zu does not have its parameter's type",
                                          inst_id,
                                          a);
                    }
                }

                if ( inst.result_type != callee.result_type )
                    _emitter.emit("call-result-type-mismatch",
                                  "core.call result type does not match its function's result type",
                                  inst_id);
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

            case Opcode::Add: {
                if ( inst.args.size() != 2 || ! _package.isValid(inst.args[0]) || ! _package.isValid(inst.args[1]) )
                    return;

                auto lhs = _package.inst(inst.args[0]).result_type;
                auto rhs = _package.inst(inst.args[1]).result_type;
                bool integer = _package.isValid(lhs) && (_package.type(lhs).kind == TypeKind::Int64 ||
                                                         _package.type(lhs).kind == TypeKind::UInt64);
                // The operands share one integer type, the one a constraint on operands would name.
                if ( lhs != rhs || ! integer )
                    _emitter.emit("operand-type-mismatch",
                                  "operand %zu does not satisfy its required type",
                                  inst_id,
                                  1);
                else if ( inst.result_type != lhs )
                    _emitter.emit("add-operand-type-mismatch",
                                  "core.add operands and result must have one 64-bit integer type",
                                  inst_id);
                return;
            }

            case Opcode::Equal: {
                if ( inst.args.size() != 2 || ! _package.isValid(inst.args[0]) || ! _package.isValid(inst.args[1]) )
                    return;

                auto lhs = _package.inst(inst.args[0]).result_type;
                auto rhs = _package.inst(inst.args[1]).result_type;
                if ( lhs != rhs || ! _package.isValid(lhs) || ! _isComparable(_package.type(lhs).kind) )
                    _emitter
                        .emit("equal-operand-type-mismatch",
                              "core.equal operands must have the same comparable type (int64, uint8, uint64, or bool)",
                              inst_id);
                return;
            }

            case Opcode::LocalPlace: {
                if ( inst.args.empty() || ! _package.isValid(inst.args[0]) )
                    return;

                // The place takes ownership of its initial value, which is affine for a vector.
                auto initial = _package.inst(inst.args[0]).result_type;
                if ( ! _package.isValid(initial) || initial == _package.voidType() ) {
                    _emitter.emit("local-place-invalid-initial",
                                  "core.local_place's initial value must be a valid, non-void, copyable value",
                                  inst_id);
                    return;
                }

                if ( ! _package.isValid(inst.result_type) || _package.type(inst.result_type).kind != TypeKind::Place ||
                     _package.type(inst.result_type).type_arguments != std::vector<TypeId>{initial} )
                    _emitter.emit("local-place-result-type-mismatch",
                                  "core.local_place result must be a place of its initial value's type",
                                  inst_id);
                return;
            }

            case Opcode::Load: {
                if ( inst.args.empty() || ! _package.isValid(inst.args[0]) )
                    return;

                auto place = _package.inst(inst.args[0]).result_type;
                if ( ! _package.isValid(place) || _package.type(place).kind != TypeKind::Place ) {
                    _emitter.emit("place-operand-mismatch", "%s requires a place operand", inst_id, "core.load");
                    return;
                }

                if ( inst.result_type != _package.type(place).type_arguments[0] )
                    _emitter.emit("load-result-type-mismatch",
                                  "core.load result must be the element type of its place",
                                  inst_id);
                else if ( _isNonCopyableOpaque(inst.result_type) )
                    _emitter.emit("opaque-load-requires-copyable",
                                  "core.load copies an opaque value whose native type does not declare copy behavior",
                                  inst_id);
                return;
            }

            case Opcode::Tuple: {
                if ( ! _package.isValid(inst.result_type) || _package.type(inst.result_type).kind != TypeKind::Tuple ) {
                    _emitter.emit("tuple-result-type-mismatch",
                                  "core.tuple result must be the tuple of its operands' types, in order",
                                  inst_id);
                    return;
                }

                const auto& elements = _package.type(inst.result_type).type_arguments;
                if ( elements.size() != inst.args.size() ) {
                    _emitter.emit("tuple-result-type-mismatch",
                                  "core.tuple result must be the tuple of its operands' types, in order",
                                  inst_id);
                    return;
                }

                for ( size_t a = 0; a < inst.args.size(); ++a )
                    if ( _package.isValid(inst.args[a]) && _package.inst(inst.args[a]).result_type != elements[a] )
                        _emitter.emit("tuple-result-type-mismatch",
                                      "core.tuple result must be the tuple of its operands' types, in order",
                                      inst_id);
                return;
            }

            case Opcode::FieldPlace: {
                const auto* payload = std::get_if<FieldPayload>(&inst.payload);
                if ( ! payload )
                    return;

                if ( ! _package.isValid(payload->field) ) {
                    _emitter.emit("field-place-invalid-payload",
                                  "unit.field_place's payload does not reference a valid field",
                                  inst_id);
                    return;
                }

                const auto& field = _package.declaration(payload->field);
                if ( inst.args.empty() || ! _package.isValid(inst.args[0]) )
                    return;

                auto unit = _package.inst(inst.args[0]).result_type;
                if ( ! _package.isValid(unit) || _package.type(unit).kind != TypeKind::Unit ||
                     _package.type(unit).declaration != field.owner )
                    _emitter.emit("field-place-unit-mismatch",
                                  "unit.field_place's operand is not a value of the unit that declares its field",
                                  inst_id);

                if ( ! _package.isValid(inst.result_type) || _package.type(inst.result_type).kind != TypeKind::Place ||
                     _package.type(inst.result_type).type_arguments != std::vector<TypeId>{field.type} )
                    _emitter.emit("field-place-result-type-mismatch",
                                  "unit.field_place result must be a place of its field's type",
                                  inst_id);
                return;
            }

            case Opcode::GlobalPlace: {
                const auto* payload = std::get_if<GlobalPayload>(&inst.payload);
                if ( ! payload )
                    return;

                if ( ! _package.isValid(payload->global) ) {
                    _emitter.emit("global-place-invalid-payload",
                                  "core.global_place's payload does not reference a valid global",
                                  inst_id);
                    return;
                }

                const auto& global = _package.global(payload->global);
                if ( ! _package.isValid(inst.result_type) || _package.type(inst.result_type).kind != TypeKind::Place ||
                     _package.type(inst.result_type).type_arguments != std::vector<TypeId>{global.type} )
                    _emitter.emit("global-place-result-type-mismatch",
                                  "core.global_place result must be a place of its global's type",
                                  inst_id);
                return;
            }

            case Opcode::Store: {
                if ( inst.args.size() != 2 || ! _package.isValid(inst.args[0]) || ! _package.isValid(inst.args[1]) )
                    return;

                auto place = _package.inst(inst.args[0]).result_type;
                if ( ! _package.isValid(place) || _package.type(place).kind != TypeKind::Place ) {
                    _emitter.emit("place-operand-mismatch", "%s requires a place operand", inst_id, "core.store");
                    return;
                }

                if ( _package.inst(inst.args[1]).result_type != _package.type(place).type_arguments[0] )
                    _emitter.emit("store-value-type-mismatch",
                                  "core.store value must be the element type of its place",
                                  inst_id);
                return;
            }

            case Opcode::OpaqueOp: {
                const auto* payload = std::get_if<ForeignFunctionPayload>(&inst.payload);
                if ( ! payload )
                    return;

                if ( ! _package.isValid(payload->function) ) {
                    _emitter.emit("opaque-op-invalid-payload",
                                  "opaque.op's payload does not reference a valid foreign function",
                                  inst_id);
                    return;
                }

                const auto& fn = _package.foreignFunction(payload->function);
                if ( inst.args.size() != fn.parameters.size() )
                    _emitter.emit("opaque-op-argument-count-mismatch",
                                  "opaque.op passes %zu argument(s) to a foreign function with %zu parameter(s)",
                                  inst_id,
                                  fn.parameters.size(),
                                  inst.args.size());
                else {
                    for ( size_t a = 0; a < inst.args.size(); ++a ) {
                        if ( ! _package.isValid(inst.args[a]) )
                            continue;

                        if ( ! _acceptsArgument(fn.parameters[a], _package.inst(inst.args[a]).result_type) )
                            _emitter.emit("opaque-op-argument-type-mismatch",
                                          "opaque.op argument %zu does not have its foreign parameter's type",
                                          inst_id,
                                          a);
                    }
                }

                if ( inst.result_type != fn.result_type )
                    _emitter.emit("opaque-op-result-type-mismatch",
                                  "opaque.op result type does not match its foreign function's result type",
                                  inst_id);
                return;
            }

            case Opcode::UnitCreate: {
                const auto* payload = std::get_if<UnitPayload>(&inst.payload);
                if ( ! payload )
                    return;

                if ( ! _package.isValid(payload->unit) ) {
                    _emitter.emit("unit-create-invalid-payload",
                                  "unit.create's payload does not reference a valid unit declaration",
                                  inst_id);
                    return;
                }

                if ( ! _package.isValid(inst.result_type) || _package.type(inst.result_type).kind != TypeKind::Unit ||
                     _package.type(inst.result_type).declaration != payload->unit )
                    _emitter.emit("unit-create-result-type-mismatch",
                                  "unit.create's result type does not match its payload's unit declaration",
                                  inst_id);
                return;
            }

            case Opcode::ReadInteger: {
                const auto* payload = std::get_if<ReadIntegerPayload>(&inst.payload);
                if ( ! payload )
                    return;

                if ( (payload->width != 8 && payload->width != 64) || payload->signedness != Signedness::Unsigned ||
                     payload->byte_order != ByteOrder::Network )
                    _emitter.emit("read-integer-unsupported-payload",
                                  "parser.read_integer only supports unsigned width-8 or width-64 network-order reads",
                                  inst_id);

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
                    _emitter.emit("read-integer-result-type-mismatch",
                                  "parser.read_integer's result type must be tuple<parser.state, uint8 or uint64> "
                                  "matching its width",
                                  inst_id);
                return;
            }

            case Opcode::PublishField: {
                const auto* payload = std::get_if<FieldPayload>(&inst.payload);
                if ( ! payload || inst.args.size() < 2 )
                    return;

                if ( ! _package.isValid(payload->field) ) {
                    _emitter.emit("publish-field-invalid-payload",
                                  "unit.publish_field's payload does not reference a valid field declaration",
                                  inst_id);
                    return;
                }

                const auto& field = _package.declaration(payload->field);

                if ( ! _package.isValid(inst.args[0]) )
                    return;

                const auto& unit_operand = _package.inst(inst.args[0]);
                if ( ! _package.isValid(unit_operand.result_type) ||
                     _package.type(unit_operand.result_type).kind != TypeKind::Unit ) {
                    _emitter.emit("publish-field-operand-not-unit",
                                  "unit.publish_field's first operand is not a unit type",
                                  inst_id);
                    return;
                }

                if ( _package.type(unit_operand.result_type).declaration != field.owner )
                    _emitter.emit("publish-field-owner-mismatch",
                                  "unit.publish_field's field is not owned by its unit operand's declaration",
                                  inst_id);

                if ( _package.isValid(inst.args[1]) && _package.inst(inst.args[1]).result_type != field.type )
                    _emitter.emit("publish-field-value-type-mismatch",
                                  "unit.publish_field's value operand does not match the field's declared type",
                                  inst_id);
                return;
            }

            case Opcode::VectorEmpty:
                if ( ! _package.isValid(inst.result_type) || _package.type(inst.result_type).kind != TypeKind::Vector )
                    _emitter.emit("invalid-parser-operation",
                                  "parser operation has inconsistent types, payload, or region signature",
                                  inst_id);
                return;

            case Opcode::VectorAppend:
                if ( inst.args.size() == 2 && _package.isValid(inst.args[0]) && _package.isValid(inst.args[1]) ) {
                    auto vector_type = _package.inst(inst.args[0]).result_type;
                    if ( ! _package.isValid(vector_type) || _package.type(vector_type).kind != TypeKind::Vector ||
                         _package.type(vector_type).type_arguments.size() != 1 ||
                         _package.type(vector_type).type_arguments[0] != _package.inst(inst.args[1]).result_type )
                        _emitter.emit("invalid-parser-operation",
                                      "parser operation has inconsistent types, payload, or region signature",
                                      inst_id);
                }
                return;

            case Opcode::EnterBound:
                if ( inst.args.size() == 2 && _package.isValid(inst.args[1]) ) {
                    auto length_type = _package.inst(inst.args[1]).result_type;
                    if ( ! _package.isValid(length_type) || (_package.type(length_type).kind != TypeKind::UInt8 &&
                                                             _package.type(length_type).kind != TypeKind::UInt64) )
                        _emitter.emit("invalid-parser-operation",
                                      "parser operation has inconsistent types, payload, or region signature",
                                      inst_id);
                }
                return;

            case Opcode::RepeatToBound: {
                if ( inst.args.empty() || ! _package.isValid(inst.args[0]) ||
                     ! _package.isValid(_package.inst(inst.args[0]).result_type) ||
                     _package.type(_package.inst(inst.args[0]).result_type).kind != TypeKind::ParserState ||
                     ! _package.isValid(inst.result_type) || _package.type(inst.result_type).kind != TypeKind::Tuple ||
                     _package.type(inst.result_type).type_arguments.size() != inst.args.size() ) {
                    _emitter.emit("invalid-parser-operation",
                                  "parser operation has inconsistent types, payload, or region signature",
                                  inst_id);
                    return;
                }
                for ( size_t i = 0; i < inst.args.size(); ++i )
                    if ( _package.isValid(inst.args[i]) &&
                         _package.type(inst.result_type).type_arguments[i] != _package.inst(inst.args[i]).result_type )
                        _emitter.emit("invalid-parser-operation",
                                      "parser operation has inconsistent types, payload, or region signature",
                                      inst_id);
                return;
            }

            case Opcode::ParseSubunit: {
                const auto* payload = std::get_if<FunctionPayload>(&inst.payload);
                if ( ! payload || ! _package.isValid(payload->function) ||
                     _package.function(payload->function).kind != FunctionKind::Parser ||
                     ! _package.isValid(inst.result_type) ) {
                    _emitter.emit("invalid-parser-operation",
                                  "parser operation has inconsistent types, payload, or region signature",
                                  inst_id);
                    return;
                }
                const auto& result = _package.type(inst.result_type);
                if ( result.kind != TypeKind::Tuple || result.type_arguments.size() != 2 ||
                     ! _package.isValid(result.type_arguments[0]) ||
                     _package.type(result.type_arguments[0]).kind != TypeKind::ParserState ||
                     result.type_arguments[1] != _package.function(payload->function).result_type )
                    _emitter.emit("invalid-parser-operation",
                                  "parser operation has inconsistent types, payload, or region signature",
                                  inst_id);
                return;
            }

            case Opcode::ReadBytes:
                if ( ! _package.isValid(inst.result_type) || _package.type(inst.result_type).kind != TypeKind::Tuple ||
                     _package.type(inst.result_type).type_arguments.size() != 2 ||
                     ! _package.isValid(_package.type(inst.result_type).type_arguments[0]) ||
                     ! _package.isValid(_package.type(inst.result_type).type_arguments[1]) ||
                     _package.type(_package.type(inst.result_type).type_arguments[0]).kind != TypeKind::ParserState ||
                     _package.type(_package.type(inst.result_type).type_arguments[1]).kind != TypeKind::Bytes )
                    _emitter.emit("invalid-parser-operation",
                                  "parser operation has inconsistent types, payload, or region signature",
                                  inst_id);
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
            case TypeKind::Set:
            case TypeKind::Opaque:
            case TypeKind::Place:
            case TypeKind::String: return false;
        }

        return false;
    }

    // A branch or jump may only target blocks of the same ordinary function body.
    void _verifySuccessor(InstId inst_id, const Inst& inst, BlockId target) {
        if ( ! _in_body || ! _cfg.contains(inst.parent) ) {
            _emitter.emit("control-flow-outside-function-body",
                          "branches and jumps are only allowed in the root region of an ordinary function",
                          inst_id);
            return;
        }

        if ( ! _package.isValid(target) || ! _cfg.contains(target) )
            _emitter.emit("invalid-successor",
                          "terminator's successor is not a block of the same function body",
                          inst_id);
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
        // The operations that only borrow an affine value, with the operand that does so, and where each is in its
        // block.
        struct Borrower {
            InstId inst;
            size_t block;
            size_t position;
            size_t operand;
        };
        std::unordered_map<uint32_t, std::vector<Borrower>> borrowed_values;
        std::unordered_map<uint32_t, std::pair<size_t, size_t>> positions;

        for ( size_t block = 0; block < count; ++block ) {
            const auto& block_insts = _package.block(_cfg.blocks[block]).insts;
            for ( size_t position = 0; position < block_insts.size(); ++position ) {
                auto inst_id = block_insts[position];
                if ( ! _package.isValid(inst_id) )
                    continue;

                positions[inst_id.index] = {block, position};
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

                if ( ! schemaFor(inst.opcode) )
                    continue;

                for ( size_t a = 0; a < inst.args.size(); ++a ) {
                    auto arg = inst.args[a];
                    if ( ! _package.isValid(arg) )
                        continue;

                    if ( typeDiscipline(_package, _package.inst(arg).result_type) != ValueDiscipline::Affine ) {
                        // A place derived from a unit is an access to that unit.
                        if ( auto owner = _derivedOwner(arg); owner.isSet() )
                            borrowed_values[owner.index].push_back(
                                {.inst = inst_id, .block = block, .position = position, .operand = a});
                        continue;
                    }

                    auto role = operandRole(_package, inst, a);
                    if ( role == OperandRole::Consume )
                        consumed_values[arg.index].push_back({.inst = inst_id, .block = block});
                    else if ( role == OperandRole::Borrow )
                        borrowed_values[arg.index].push_back(
                            {.inst = inst_id, .block = block, .position = position, .operand = a});
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
                        _emitter.emit("parser-state-reused",
                                      "parser state value is consumed by more than one state-transforming operation",
                                      b.inst);
                        break;
                    }
                }
            }
        };

        for ( const auto& [_, consumers] : consumed_values )
            check(consumers);

        // A borrow must not follow a consumption on any path.
        for ( const auto& [value, consumers] : consumed_values ) {
            auto borrowers = borrowed_values.find(value);
            if ( borrowers == borrowed_values.end() )
                continue;

            for ( const auto& borrower : borrowers->second ) {
                for ( const auto& consumer : consumers ) {
                    bool after = consumer.block == borrower.block ?
                                     positions.at(consumer.inst.index).second < borrower.position :
                                     reaches[consumer.block][borrower.block];
                    if ( after ) {
                        _emitter.emit("use-after-consume",
                                      "operand %zu uses an affine value after an operation consumed it",
                                      borrower.inst,
                                      borrower.operand);
                        break;
                    }
                }
            }
        }
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
            _emitter.emit("invalid-operand-id", "operand %zu is not a valid instruction ID", user, operand_index);
            return;
        }

        const auto& arg_inst = _package.inst(arg);

        if ( arg_inst.parent != block_id ) {
            if ( ! _availableFrom(arg_inst.parent, block_id) ) {
                _emitter.emit("operand-not-same-block",
                              "operand %zu is not defined in the same block",
                              user,
                              operand_index);
                return;
            }
        }
        else if ( ! defined.contains(arg.index) ) {
            _emitter.emit("operand-used-before-definition",
                          "operand %zu is used before it is defined",
                          user,
                          operand_index);
            return;
        }

        if ( arg_inst.result_type == _package.voidType() )
            _emitter.emit("void-operand-used", "operand %zu has void type and cannot be used", user, operand_index);

        if ( constraint && ! _satisfies(*constraint, arg_inst.result_type, function_result_type) ) {
            if ( constraint->kind == TypeConstraintKind::SameAsFunctionResult )
                _emitter
                    .emit("return-type-mismatch",
                          "returned value has type %s, expected %s",
                          user,
                          typeName(_package, arg_inst.result_type),
                          typeName(_package, function_result_type))
                    .note("function-declared-here",
                          "function declared with result type %s",
                          function_id,
                          typeName(_package, function_result_type));
            else
                _emitter
                    .emit("operand-type-mismatch",
                          "operand %zu does not satisfy its required type",
                          user,
                          operand_index)
                    .note("operand-defined-here", "operand defined here", arg);
        }
    }

    void _verifyResultType(InstId inst_id, const Inst& inst, const OpcodeSchema& schema) {
        switch ( schema.result_type.kind ) {
            case TypeConstraintKind::Any: return;

            case TypeConstraintKind::Fixed:
                if ( ! _satisfies(schema.result_type, inst.result_type, TypeId{}) )
                    _emitter.emit("result-type-mismatch",
                                  "instruction's result type does not satisfy its required type",
                                  inst_id);
                return;

            case TypeConstraintKind::SameAsOperand: {
                if ( inst.args.empty() )
                    return;

                auto operand = inst.args[0];
                if ( ! _package.isValid(operand) )
                    return;

                if ( inst.result_type != _package.inst(operand).result_type )
                    _emitter.emit("result-type-mismatch",
                                  "instruction's result type does not satisfy its required type",
                                  inst_id);
                return;
            }

            case TypeConstraintKind::SameAsFunctionResult: return;
        }
    }

    const Package& _package;
    InternalErrorEmitter _emitter;
    std::unordered_set<uint32_t> _active_regions;
    std::unordered_set<uint32_t> _owned_regions;
    // The CFG and dominator tree of the ordinary function body being verified, if any.
    bool _in_body = false;
    Cfg _cfg;
    std::vector<size_t> _idom;
};

} // namespace

std::vector<InternalError> verify(const Package& package) {
    std::vector<InternalError> errors;
    Verifier verifier(package, errors);
    InternalErrorEmitter emitter(package, errors);

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
            emitter.emit("duplicate-parser-root-unit",
                         "unit declaration is the target of more than one parser root",
                         root.unit);

        verifier.verifyParserRoot(root);
    }

    for ( auto root : package.functionRoots() ) {
        if ( ! package.isValid(root) )
            emitter.emit("invalid-function-root", "function root does not reference a valid function", noSite());
        else if ( package.function(root).kind != FunctionKind::Normal )
            emitter.emit("function-root-not-normal", "function root must be an ordinary function", root);
    }

    auto reach = computeReachableIds(package);

    for ( auto id : reach.duplicate_regions )
        emitter.emit("duplicate-region-ownership", "region is owned by more than one function", id);
    for ( auto id : reach.duplicate_blocks )
        emitter.emit("duplicate-block-ownership", "block belongs to more than one function's region", id);
    for ( auto id : reach.duplicate_insts )
        emitter.emit("duplicate-instruction-ownership", "instruction belongs to more than one block", id);

    if ( reach.regions.size() != package.regions().size() )
        emitter.emit("orphan-regions",
                     "package contains %zu unattached region(s)",
                     noSite(),
                     package.regions().size() - reach.regions.size());
    if ( reach.blocks.size() != package.blocks().size() )
        emitter.emit("orphan-blocks",
                     "package contains %zu unattached block(s)",
                     noSite(),
                     package.blocks().size() - reach.blocks.size());
    if ( reach.insts.size() != package.instructions().size() )
        emitter.emit("orphan-instructions",
                     "package contains %zu unattached instruction(s)",
                     noSite(),
                     package.instructions().size() - reach.insts.size());

    return errors;
}

} // namespace spicy::detail::pir::ir
