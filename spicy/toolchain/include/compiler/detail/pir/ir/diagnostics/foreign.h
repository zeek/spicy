// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <spicy/compiler/detail/pir/ir/diagnostic-definition.h>

namespace spicy::detail::pir::ir::diag {

// --- Opaque types and foreign function declarations ----------------------------------------------

inline constexpr DiagnosticDefinition TypeOpaqueMissingDeclaration{
    .id = "PIR_TYPE_OPAQUE_MISSING_DECLARATION",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "opaque type does not reference an opaque type declaration",
};

inline constexpr DiagnosticDefinition TypeDeclOpaqueInfoMismatch{
    .id = "PIR_TYPE_DECL_OPAQUE_INFO_MISMATCH",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "native binding information must be present exactly for opaque type declarations",
};

inline constexpr DiagnosticDefinition OpaqueDeclarationIncomplete{
    .id = "PIR_OPAQUE_DECLARATION_INCOMPLETE",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "opaque type declaration must name its native type and declare its lifecycle",
};

inline constexpr DiagnosticDefinition ForeignFunctionMissingBinding{
    .id = "PIR_FOREIGN_FUNCTION_MISSING_BINDING",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "foreign function must either name its native symbol or be provided by the target",
};

inline constexpr DiagnosticDefinition ForeignFunctionInvalidResult{
    .id = "PIR_FOREIGN_FUNCTION_INVALID_RESULT",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "foreign function result must be a valid type that a native call returns by value",
};

inline constexpr DiagnosticDefinition ForeignFunctionInvalidParameter{
    .id = "PIR_FOREIGN_FUNCTION_INVALID_PARAMETER",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "foreign function parameter %zu must be a valid type that a native call accepts by value",
};

inline constexpr DiagnosticDefinition OpaqueLoadRequiresCopyable{
    .id = "PIR_OPAQUE_LOAD_REQUIRES_COPYABLE",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "core.load copies an opaque value whose native type does not declare copy behavior",
};

inline constexpr DiagnosticDefinition OpaqueOpInvalidPayload{
    .id = "PIR_OPAQUE_OP_INVALID_PAYLOAD",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "opaque.op's payload does not reference a valid foreign function",
};

inline constexpr DiagnosticDefinition OpaqueOpArgumentCountMismatch{
    .id = "PIR_OPAQUE_OP_ARGUMENT_COUNT_MISMATCH",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "opaque.op passes %zu argument(s) to a foreign function with %zu parameter(s)",
};

inline constexpr DiagnosticDefinition OpaqueOpArgumentTypeMismatch{
    .id = "PIR_OPAQUE_OP_ARGUMENT_TYPE_MISMATCH",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "opaque.op argument %zu does not have its foreign parameter's type",
};

inline constexpr DiagnosticDefinition OpaqueOpResultTypeMismatch{
    .id = "PIR_OPAQUE_OP_RESULT_TYPE_MISMATCH",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "opaque.op result type does not match its foreign function's result type",
};

} // namespace spicy::detail::pir::ir::diag
