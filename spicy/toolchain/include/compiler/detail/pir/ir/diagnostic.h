// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include <hilti/base/util.h>

#include <spicy/compiler/detail/pir/ir/package.h>
#include <spicy/compiler/detail/pir/ir/source.h>

namespace spicy::detail::pir::ir {

enum class DiagnosticSeverity { Error, Warning, Note };

/**
 * Whether a diagnostic reports a violated PIR invariant (an internal compiler error, never
 * suppressible and not the user's fault) or a source-level condition a user could address.
 * Every diagnostic PIR's verifier currently produces is `Internal`: they all report malformed
 * PIR, which is a compiler bug, not something a well-formed Spicy program can trigger.
 */
enum class DiagnosticClassification { Internal, User };

/** A catalog entry fixing one diagnostic's stable ID, classification, severity, and message format. */
struct DiagnosticDefinition {
    const char* id;
    DiagnosticClassification classification;
    DiagnosticSeverity severity;
    const char* message;
};

/** Definitions are identified by their stable ID; there is exactly one per catalog entry. */
constexpr bool operator==(const DiagnosticDefinition& a, const DiagnosticDefinition& b) {
    return std::string_view(a.id) == std::string_view(b.id);
}
constexpr bool operator!=(const DiagnosticDefinition& a, const DiagnosticDefinition& b) { return ! (a == b); }

namespace diag {

inline constexpr DiagnosticDefinition InvalidFunctionResultType{
    .id = "PIR_INVALID_FUNCTION_RESULT_TYPE",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "function's result type is not a valid type ID",
};

inline constexpr DiagnosticDefinition InvalidRootRegion{
    .id = "PIR_INVALID_ROOT_REGION",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "function's root region is not a valid region ID",
};

inline constexpr DiagnosticDefinition RegionBlockCountMismatch{
    .id = "PIR_REGION_BLOCK_COUNT_MISMATCH",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "function's region must contain exactly one block, has %zu",
};

inline constexpr DiagnosticDefinition InvalidBlockId{
    .id = "PIR_INVALID_BLOCK_ID",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "region references an invalid block ID",
};

inline constexpr DiagnosticDefinition EmptyBlock{
    .id = "PIR_EMPTY_BLOCK",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "block has no instructions and therefore no terminator",
};

inline constexpr DiagnosticDefinition InvalidInstructionId{
    .id = "PIR_INVALID_INSTRUCTION_ID",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "instruction at position %zu has an invalid ID",
};

inline constexpr DiagnosticDefinition CachedParentMismatch{
    .id = "PIR_CACHED_PARENT_MISMATCH",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "instruction's cached parent block (%%%u) does not match its containing block (%%%u)",
};

inline constexpr DiagnosticDefinition UnrecognizedOpcode{
    .id = "PIR_UNRECOGNIZED_OPCODE",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "unrecognized opcode",
};

inline constexpr DiagnosticDefinition TerminatorNotLast{
    .id = "PIR_TERMINATOR_NOT_LAST",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "terminator is not the last instruction in its block",
};

inline constexpr DiagnosticDefinition MissingTerminator{
    .id = "PIR_MISSING_TERMINATOR",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "block does not end in a terminator",
};

inline constexpr DiagnosticDefinition OperandCountMismatch{
    .id = "PIR_OPERAND_COUNT_MISMATCH",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "expected %zu operand(s), got %zu",
};

inline constexpr DiagnosticDefinition UnexpectedPayload{
    .id = "PIR_UNEXPECTED_PAYLOAD",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "unexpected integer payload",
};

inline constexpr DiagnosticDefinition MissingPayload{
    .id = "PIR_MISSING_PAYLOAD",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "missing required integer payload",
};

inline constexpr DiagnosticDefinition InvalidOperandId{
    .id = "PIR_INVALID_OPERAND_ID",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "operand %zu is not a valid instruction ID",
};

inline constexpr DiagnosticDefinition OperandNotSameBlock{
    .id = "PIR_OPERAND_NOT_SAME_BLOCK",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "operand %zu is not defined in the same block",
};

inline constexpr DiagnosticDefinition OperandUsedBeforeDefinition{
    .id = "PIR_OPERAND_USED_BEFORE_DEFINITION",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "operand %zu is used before it is defined",
};

inline constexpr DiagnosticDefinition VoidOperandUsed{
    .id = "PIR_VOID_OPERAND_USED",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "operand %zu has void type and cannot be used",
};

inline constexpr DiagnosticDefinition OperandTypeMismatch{
    .id = "PIR_OPERAND_TYPE_MISMATCH",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "operand %zu does not satisfy its required type",
};

inline constexpr DiagnosticDefinition ResultTypeMismatch{
    .id = "PIR_RESULT_TYPE_MISMATCH",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "instruction's result type does not satisfy its required type",
};

inline constexpr DiagnosticDefinition ReturnTypeMismatch{
    .id = "PIR_RETURN_TYPE_MISMATCH",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "returned value has type %s, expected %s",
};

inline constexpr DiagnosticDefinition DuplicateRegionOwnership{
    .id = "PIR_DUPLICATE_REGION_OWNERSHIP",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "region is owned by more than one function",
};

inline constexpr DiagnosticDefinition DuplicateBlockOwnership{
    .id = "PIR_DUPLICATE_BLOCK_OWNERSHIP",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "block belongs to more than one function's region",
};

inline constexpr DiagnosticDefinition DuplicateInstructionOwnership{
    .id = "PIR_DUPLICATE_INSTRUCTION_OWNERSHIP",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "instruction belongs to more than one block",
};

inline constexpr DiagnosticDefinition OrphanRegions{
    .id = "PIR_ORPHAN_REGIONS",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "package contains %zu unattached region(s)",
};

inline constexpr DiagnosticDefinition OrphanBlocks{
    .id = "PIR_ORPHAN_BLOCKS",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "package contains %zu unattached block(s)",
};

inline constexpr DiagnosticDefinition OrphanInstructions{
    .id = "PIR_ORPHAN_INSTRUCTIONS",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "package contains %zu unattached instruction(s)",
};

inline constexpr DiagnosticDefinition InvalidSourceSpanId{
    .id = "PIR_INVALID_SOURCE_SPAN_ID",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "reference to an invalid source span ID",
};

inline constexpr DiagnosticDefinition InvalidSourceFileId{
    .id = "PIR_INVALID_SOURCE_FILE_ID",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "source span references an invalid source file ID",
};

inline constexpr DiagnosticDefinition MalformedSourceSpanRange{
    .id = "PIR_MALFORMED_SOURCE_SPAN_RANGE",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "source span has a reversed %s range",
};

inline constexpr DiagnosticDefinition FunctionDeclaredHere{
    .id = "PIR_FUNCTION_DECLARED_HERE",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Note,
    .message = "function declared with result type %s",
};

inline constexpr DiagnosticDefinition OperandDefinedHere{
    .id = "PIR_OPERAND_DEFINED_HERE",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Note,
    .message = "operand defined here",
};

inline constexpr DiagnosticDefinition TypeMissingDeclaration{
    .id = "PIR_TYPE_MISSING_DECLARATION",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "unit type does not reference a valid type declaration",
};

inline constexpr DiagnosticDefinition TypeUnexpectedDeclaration{
    .id = "PIR_TYPE_UNEXPECTED_DECLARATION",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "only a unit type may carry a type declaration",
};

inline constexpr DiagnosticDefinition TypeInvalidTypeArgument{
    .id = "PIR_TYPE_INVALID_TYPE_ARGUMENT",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "tuple type argument %zu is not a valid type ID",
};

inline constexpr DiagnosticDefinition TypeUnexpectedTypeArguments{
    .id = "PIR_TYPE_UNEXPECTED_TYPE_ARGUMENTS",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "only a tuple type may carry type arguments",
};

inline constexpr DiagnosticDefinition InvalidFieldDeclarationId{
    .id = "PIR_INVALID_FIELD_DECLARATION_ID",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "unit declaration references an invalid field ID",
};

inline constexpr DiagnosticDefinition FieldOwnerMismatch{
    .id = "PIR_FIELD_OWNER_MISMATCH",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "field's cached owner does not match the unit declaring it",
};

inline constexpr DiagnosticDefinition InvalidFieldType{
    .id = "PIR_INVALID_FIELD_TYPE",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "field does not reference a valid type ID",
};

// --- Declaration membership --------------------------------------------------------------------

inline constexpr DiagnosticDefinition DeclarationInvalidOwner{
    .id = "PIR_DECLARATION_INVALID_OWNER",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "declaration's owner is not a valid type declaration ID",
};

inline constexpr DiagnosticDefinition DeclarationNotInOwnerMembership{
    .id = "PIR_DECLARATION_NOT_IN_OWNER_MEMBERSHIP",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "declaration does not appear in its owner's membership vector",
};

inline constexpr DiagnosticDefinition DeclarationDuplicateOwnerMembership{
    .id = "PIR_DECLARATION_DUPLICATE_OWNER_MEMBERSHIP",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "declaration appears more than once in its owner's membership vector",
};

// --- Parser roots -----------------------------------------------------------------------------

inline constexpr DiagnosticDefinition DuplicateParserRootUnit{
    .id = "PIR_DUPLICATE_PARSER_ROOT_UNIT",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "unit declaration is the target of more than one parser root",
};

inline constexpr DiagnosticDefinition InvalidParserRootUnit{
    .id = "PIR_INVALID_PARSER_ROOT_UNIT",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "parser root references an invalid unit declaration",
};

inline constexpr DiagnosticDefinition InvalidParserRootFunction{
    .id = "PIR_INVALID_PARSER_ROOT_FUNCTION",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "parser root references an invalid function",
};

inline constexpr DiagnosticDefinition ParserRootFunctionKindMismatch{
    .id = "PIR_PARSER_ROOT_FUNCTION_KIND_MISMATCH",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "parser root's function is not a parser function",
};

inline constexpr DiagnosticDefinition ParserRootUnitMismatch{
    .id = "PIR_PARSER_ROOT_UNIT_MISMATCH",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "parser root's unit does not match its function's parser unit",
};

// --- Function kind/signature/parser-unit consistency -------------------------------------------

inline constexpr DiagnosticDefinition NormalFunctionWithParserUnit{
    .id = "PIR_NORMAL_FUNCTION_WITH_PARSER_UNIT",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "an ordinary function must not reference a parser unit",
};

inline constexpr DiagnosticDefinition ParserFunctionMissingParserUnit{
    .id = "PIR_PARSER_FUNCTION_MISSING_PARSER_UNIT",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "a parser function must reference a valid parser unit",
};

inline constexpr DiagnosticDefinition ParserFunctionParameterCountMismatch{
    .id = "PIR_PARSER_FUNCTION_PARAMETER_COUNT_MISMATCH",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "a parser function must have exactly one parameter, has %zu",
};

inline constexpr DiagnosticDefinition ParserFunctionParameterTypeMismatch{
    .id = "PIR_PARSER_FUNCTION_PARAMETER_TYPE_MISMATCH",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "a parser function's parameter must be parser.state",
};

inline constexpr DiagnosticDefinition ParserFunctionResultTypeMismatch{
    .id = "PIR_PARSER_FUNCTION_RESULT_TYPE_MISMATCH",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "a parser function's result type must be its parser unit's nominal type",
};

// --- core.argument -----------------------------------------------------------------------------

inline constexpr DiagnosticDefinition ArgumentNotLeading{
    .id = "PIR_ARGUMENT_NOT_LEADING",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "core.argument must appear before any non-argument instruction in the entry block",
};

inline constexpr DiagnosticDefinition ArgumentIndexOutOfRange{
    .id = "PIR_ARGUMENT_INDEX_OUT_OF_RANGE",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "core.argument index %u is out of range for %zu parameter(s)",
};

inline constexpr DiagnosticDefinition ArgumentIndexDuplicate{
    .id = "PIR_ARGUMENT_INDEX_DUPLICATE",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "core.argument index %u is bound more than once",
};

inline constexpr DiagnosticDefinition ArgumentIndexMissing{
    .id = "PIR_ARGUMENT_INDEX_MISSING",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "function parameter %zu has no core.argument binding it",
};

inline constexpr DiagnosticDefinition ArgumentResultTypeMismatch{
    .id = "PIR_ARGUMENT_RESULT_TYPE_MISMATCH",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "core.argument's result type does not match its function's parameter type",
};

// --- Opcode-specific dynamic result/operand construction ---------------------------------------

inline constexpr DiagnosticDefinition TupleGetOperandNotTuple{
    .id = "PIR_TUPLE_GET_OPERAND_NOT_TUPLE",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "core.tuple_get's operand is not a tuple type",
};

inline constexpr DiagnosticDefinition TupleGetIndexOutOfRange{
    .id = "PIR_TUPLE_GET_INDEX_OUT_OF_RANGE",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "core.tuple_get index %u is out of range for a %zu-element tuple",
};

inline constexpr DiagnosticDefinition TupleGetResultTypeMismatch{
    .id = "PIR_TUPLE_GET_RESULT_TYPE_MISMATCH",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "core.tuple_get's result type does not match the selected tuple element",
};

inline constexpr DiagnosticDefinition UnitCreateInvalidPayload{
    .id = "PIR_UNIT_CREATE_INVALID_PAYLOAD",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "unit.create's payload does not reference a valid unit declaration",
};

inline constexpr DiagnosticDefinition UnitCreateResultTypeMismatch{
    .id = "PIR_UNIT_CREATE_RESULT_TYPE_MISMATCH",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "unit.create's result type does not match its payload's unit declaration",
};

inline constexpr DiagnosticDefinition ReadIntegerUnsupportedPayload{
    .id = "PIR_READ_INTEGER_UNSUPPORTED_PAYLOAD",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "parser.read_integer only supports unsigned width-8 network-order reads in this slice",
};

inline constexpr DiagnosticDefinition ReadIntegerResultTypeMismatch{
    .id = "PIR_READ_INTEGER_RESULT_TYPE_MISMATCH",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "parser.read_integer's result type must be tuple<parser.state, uint8>",
};

inline constexpr DiagnosticDefinition PublishFieldInvalidPayload{
    .id = "PIR_PUBLISH_FIELD_INVALID_PAYLOAD",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "unit.publish_field's payload does not reference a valid field declaration",
};

inline constexpr DiagnosticDefinition PublishFieldOperandNotUnit{
    .id = "PIR_PUBLISH_FIELD_OPERAND_NOT_UNIT",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "unit.publish_field's first operand is not a unit type",
};

inline constexpr DiagnosticDefinition PublishFieldOwnerMismatch{
    .id = "PIR_PUBLISH_FIELD_OWNER_MISMATCH",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "unit.publish_field's field is not owned by its unit operand's declaration",
};

inline constexpr DiagnosticDefinition FinishInNormalFunction{
    .id = "PIR_FINISH_IN_NORMAL_FUNCTION",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "parser.finish may only terminate a parser function",
};

inline constexpr DiagnosticDefinition PublishFieldValueTypeMismatch{
    .id = "PIR_PUBLISH_FIELD_VALUE_TYPE_MISMATCH",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "unit.publish_field's value operand does not match the field's declared type",
};

// --- Parser- and unit-state affinity -------------------------------------------------------------

inline constexpr DiagnosticDefinition ParserStateReused{
    .id = "PIR_PARSER_STATE_REUSED",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "parser state value is consumed by more than one state-transforming operation",
};

inline constexpr DiagnosticDefinition UnitStateStaleOrUnknownOperand{
    .id = "PIR_UNIT_STATE_STALE_OR_UNKNOWN_OPERAND",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "operand does not reference a live unit-state value created earlier in this function",
};

inline constexpr DiagnosticDefinition DuplicateFieldPublication{
    .id = "PIR_DUPLICATE_FIELD_PUBLICATION",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "field is published more than once",
};

inline constexpr DiagnosticDefinition MissingFieldPublication{
    .id = "PIR_MISSING_FIELD_PUBLICATION",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "parser.finish completes a unit that has not published all of its fields",
};

} // namespace diag

/** A typed anchor for a diagnostic; `std::monostate` means no typed entity is available. */
using DiagnosticEntity =
    std::variant<std::monostate, FunctionId, RegionId, BlockId, InstId, TypeId, TypeDeclId, DeclId>;

/** Where a diagnostic (or note) points: an optional source span plus an optional typed IR anchor. */
struct DiagnosticSite {
    SourceSpanId source; /**< invalid means absent */
    DiagnosticEntity entity;
};

/** An explicit "nowhere" site, for diagnostics about the package as a whole. */
inline DiagnosticSite noSite() { return DiagnosticSite{}; }

struct DiagnosticNote {
    DiagnosticDefinition definition;
    std::string message; /**< formatted through `definition.message` */
    DiagnosticSite site;
};

/** A diagnostic carries the exact catalog definition it was raised from, not a re-derived copy. */
struct Diagnostic {
    DiagnosticDefinition definition;
    std::string message; /**< formatted through `definition.message` */
    DiagnosticSite primary;
    std::vector<DiagnosticNote> notes;
};

namespace detail {

// Overloaded on the anchor type so `emit()`/`note()` can accept a typed entity directly and
// have the emitter derive its site (and, for `FunctionId`/`InstId`, its stored source span)
// automatically. `Package` lookups happen here rather than at call sites.
inline DiagnosticSite siteFor(const Package& package, FunctionId id) {
    SourceSpanId span;
    if ( package.isValid(id) )
        span = package.function(id).span;
    return DiagnosticSite{.source = span, .entity = id};
}

inline DiagnosticSite siteFor(const Package& package, InstId id) {
    SourceSpanId span;
    if ( package.isValid(id) )
        span = package.inst(id).span;
    return DiagnosticSite{.source = span, .entity = id};
}

inline DiagnosticSite siteFor(const Package& /* package */, RegionId id) { return DiagnosticSite{.entity = id}; }

inline DiagnosticSite siteFor(const Package& /* package */, BlockId id) { return DiagnosticSite{.entity = id}; }

inline DiagnosticSite siteFor(const Package& /* package */, TypeId id) { return DiagnosticSite{.entity = id}; }

inline DiagnosticSite siteFor(const Package& package, TypeDeclId id) {
    SourceSpanId span;
    if ( package.isValid(id) )
        span = package.typeDecl(id).span;
    return DiagnosticSite{.source = span, .entity = id};
}

inline DiagnosticSite siteFor(const Package& package, DeclId id) {
    SourceSpanId span;
    if ( package.isValid(id) )
        span = package.declaration(id).span;
    return DiagnosticSite{.source = span, .entity = id};
}

inline DiagnosticSite siteFor(const Package& /* package */, SourceSpanId span) {
    return DiagnosticSite{.source = span};
}

inline DiagnosticSite siteFor(const Package& /* package */, DiagnosticSite site) { return site; }

} // namespace detail

/** Appends notes to the diagnostic most recently emitted through the owning `DiagnosticEmitter`. */
class DiagnosticBuilder {
public:
    DiagnosticBuilder(const Package& package, std::vector<Diagnostic>& sink, size_t index)
        : _package(package), _sink(sink), _index(index) {}

    template<typename Anchor, typename... Args>
    DiagnosticBuilder& note(const DiagnosticDefinition& def, const Anchor& anchor, const Args&... args) {
        _sink[_index].notes.push_back(DiagnosticNote{
            .definition = def,
            .message = hilti::util::fmt(def.message, args...),
            .site = detail::siteFor(_package, anchor),
        });
        return *this;
    }

private:
    const Package& _package;
    std::vector<Diagnostic>& _sink;
    size_t _index;
};

/**
 * Formats and appends diagnostics through catalog definitions. The emitter is package-aware so
 * callers pass a typed anchor (`FunctionId`, `InstId`, `RegionId`, `BlockId`, `SourceSpanId`, or
 * `noSite()`) directly rather than constructing a `DiagnosticSite`; `FunctionId` and `InstId`
 * anchors automatically pick up that entity's stored source span.
 */
class DiagnosticEmitter {
public:
    DiagnosticEmitter(const Package& package, std::vector<Diagnostic>& sink) : _package(package), _sink(sink) {}

    template<typename Anchor, typename... Args>
    DiagnosticBuilder emit(const DiagnosticDefinition& def, const Anchor& anchor, const Args&... args) {
        _sink.push_back(Diagnostic{
            .definition = def,
            .message = hilti::util::fmt(def.message, args...),
            .primary = detail::siteFor(_package, anchor),
            .notes = {},
        });
        return DiagnosticBuilder(_package, _sink, _sink.size() - 1);
    }

private:
    const Package& _package;
    std::vector<Diagnostic>& _sink;
};

/** Renders diagnostics deterministically; tolerant of malformed source/entity references. */
std::string render(const Package& package, const std::vector<Diagnostic>& diagnostics);

} // namespace spicy::detail::pir::ir
