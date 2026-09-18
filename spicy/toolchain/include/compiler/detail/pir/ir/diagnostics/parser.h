// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <spicy/compiler/detail/pir/ir/diagnostic-definition.h>

namespace spicy::detail::pir::ir::diag {

// --- unit.create -------------------------------------------------------------------------------

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

// --- parser.read_integer -------------------------------------------------------------------------

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

// --- unit.publish_field --------------------------------------------------------------------------

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

inline constexpr DiagnosticDefinition PublishFieldValueTypeMismatch{
    .id = "PIR_PUBLISH_FIELD_VALUE_TYPE_MISMATCH",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "unit.publish_field's value operand does not match the field's declared type",
};

// --- parser.finish --------------------------------------------------------------------------

inline constexpr DiagnosticDefinition FinishInNormalFunction{
    .id = "PIR_FINISH_IN_NORMAL_FUNCTION",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "parser.finish may only terminate a parser function",
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

} // namespace spicy::detail::pir::ir::diag
