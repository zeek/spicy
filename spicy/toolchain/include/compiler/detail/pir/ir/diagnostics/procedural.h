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
    .message = "parameter %zu of an ordinary function must be a valid, non-void, copyable or place type",
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

inline constexpr DiagnosticDefinition StoreValueTypeMismatch{
    .id = "PIR_STORE_VALUE_TYPE_MISMATCH",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "core.store value must be the element type of its place",
};

} // namespace spicy::detail::pir::ir::diag
