// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <spicy/compiler/detail/pir/ir/diagnostic-definition.h>

namespace spicy::detail::pir::ir::diag {

// --- Places and ordinary calls -----------------------------------------------------------------

inline constexpr DiagnosticDefinition PlaceMissingElement{
    .id = "PIR_PLACE_MISSING_ELEMENT",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "place type must carry exactly one valid element type argument",
};

inline constexpr DiagnosticDefinition PlaceEscapes{
    .id = "PIR_PLACE_ESCAPES",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "a place may only be a parameter or an operand, not a function result, field, or element",
};

inline constexpr DiagnosticDefinition InvalidFunctionRoot{
    .id = "PIR_INVALID_FUNCTION_ROOT",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "function root does not reference a valid function",
};

inline constexpr DiagnosticDefinition FunctionRootNotNormal{
    .id = "PIR_FUNCTION_ROOT_NOT_NORMAL",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "function root must be an ordinary function",
};

inline constexpr DiagnosticDefinition NormalFunctionInvalidParameter{
    .id = "PIR_NORMAL_FUNCTION_INVALID_PARAMETER",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message =
        "parameter %zu of an ordinary function must have a valid type for its mode: a taken value is not a place, "
        "and a borrow is a place or an affine value",
};

inline constexpr DiagnosticDefinition CallTargetNotNormal{
    .id = "PIR_CALL_TARGET_NOT_NORMAL",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "core.call must target an ordinary function",
};

inline constexpr DiagnosticDefinition CallInvalidPayload{
    .id = "PIR_CALL_INVALID_PAYLOAD",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "core.call's payload does not reference a valid function",
};

inline constexpr DiagnosticDefinition CallArgumentCountMismatch{
    .id = "PIR_CALL_ARGUMENT_COUNT_MISMATCH",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "core.call passes %zu argument(s) to a function with %zu parameter(s)",
};

inline constexpr DiagnosticDefinition CallArgumentTypeMismatch{
    .id = "PIR_CALL_ARGUMENT_TYPE_MISMATCH",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "core.call argument %zu does not have its parameter's type",
};

inline constexpr DiagnosticDefinition CallResultTypeMismatch{
    .id = "PIR_CALL_RESULT_TYPE_MISMATCH",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "core.call result type does not match its function's result type",
};

inline constexpr DiagnosticDefinition LocalPlaceInvalidInitial{
    .id = "PIR_LOCAL_PLACE_INVALID_INITIAL",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "core.local_place's initial value must be a valid, non-void, copyable value",
};

inline constexpr DiagnosticDefinition LocalPlaceResultTypeMismatch{
    .id = "PIR_LOCAL_PLACE_RESULT_TYPE_MISMATCH",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "core.local_place result must be a place of its initial value's type",
};

inline constexpr DiagnosticDefinition PlaceOperandMismatch{
    .id = "PIR_PLACE_OPERAND_MISMATCH",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "%s requires a place operand",
};

inline constexpr DiagnosticDefinition LoadResultTypeMismatch{
    .id = "PIR_LOAD_RESULT_TYPE_MISMATCH",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "core.load result must be the element type of its place",
};

inline constexpr DiagnosticDefinition TupleResultTypeMismatch{
    .id = "PIR_TUPLE_RESULT_TYPE_MISMATCH",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "core.tuple result must be the tuple of its operands' types, in order",
};

inline constexpr DiagnosticDefinition FieldPlaceInvalidPayload{
    .id = "PIR_FIELD_PLACE_INVALID_PAYLOAD",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "unit.field_place's payload does not reference a valid field",
};

inline constexpr DiagnosticDefinition FieldPlaceUnitMismatch{
    .id = "PIR_FIELD_PLACE_UNIT_MISMATCH",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "unit.field_place's operand is not a value of the unit that declares its field",
};

inline constexpr DiagnosticDefinition FieldPlaceResultTypeMismatch{
    .id = "PIR_FIELD_PLACE_RESULT_TYPE_MISMATCH",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "unit.field_place result must be a place of its field's type",
};

inline constexpr DiagnosticDefinition GlobalPlaceInvalidPayload{
    .id = "PIR_GLOBAL_PLACE_INVALID_PAYLOAD",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "core.global_place's payload does not reference a valid global",
};

inline constexpr DiagnosticDefinition AddOperandTypeMismatch{
    .id = "PIR_ADD_OPERAND_TYPE_MISMATCH",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "core.add operands and result must have one 64-bit integer type",
};

inline constexpr DiagnosticDefinition GlobalPlaceResultTypeMismatch{
    .id = "PIR_GLOBAL_PLACE_RESULT_TYPE_MISMATCH",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "core.global_place result must be a place of its global's type",
};

inline constexpr DiagnosticDefinition StoreValueTypeMismatch{
    .id = "PIR_STORE_VALUE_TYPE_MISMATCH",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "core.store value must be the element type of its place",
};

// --- Borrowed parameters --------------------------------------------------------------------------

inline constexpr DiagnosticDefinition BorrowedValueConsumed{
    .id = "PIR_BORROWED_VALUE_CONSUMED",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "operand %zu consumes a value that was only borrowed; its owner is the caller",
};

inline constexpr DiagnosticDefinition BorrowEscapes{
    .id = "PIR_BORROW_ESCAPES",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "a borrowed value cannot be returned, because the borrow ends with the call",
};

inline constexpr DiagnosticDefinition BorrowWriteDenied{
    .id = "PIR_BORROW_WRITE_DENIED",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "operand %zu requires write access, but it derives from a read-only borrow",
};

inline constexpr DiagnosticDefinition UseAfterConsume{
    .id = "PIR_USE_AFTER_CONSUME",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "operand %zu uses an affine value after an operation consumed it",
};

} // namespace spicy::detail::pir::ir::diag
