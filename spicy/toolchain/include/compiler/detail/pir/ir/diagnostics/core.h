// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <spicy/compiler/detail/pir/ir/diagnostic-definition.h>

namespace spicy::detail::pir::ir::diag {

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

// --- core.tuple_get ------------------------------------------------------------------------------

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

} // namespace spicy::detail::pir::ir::diag
