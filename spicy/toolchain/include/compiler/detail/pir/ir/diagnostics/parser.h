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
    .message = "parser.read_integer only supports unsigned width-8 or width-64 network-order reads",
};

inline constexpr DiagnosticDefinition ReadIntegerResultTypeMismatch{
    .id = "PIR_READ_INTEGER_RESULT_TYPE_MISMATCH",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "parser.read_integer's result type must be tuple<parser.state, uint8 or uint64> matching its width",
};

inline constexpr DiagnosticDefinition InvalidParserOperation{
    .id = "PIR_INVALID_PARSER_OPERATION",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "parser operation has inconsistent types, payload, or region signature",
};

inline constexpr DiagnosticDefinition InvalidRegionArgument{
    .id = "PIR_INVALID_REGION_ARGUMENT",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "region argument is not a leading argument with the expected type and index",
};

inline constexpr DiagnosticDefinition InvalidYield{
    .id = "PIR_INVALID_YIELD",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "region yield does not match its owner's carried values",
};

inline constexpr DiagnosticDefinition InvalidStructuredRegion{
    .id = "PIR_INVALID_STRUCTURED_REGION",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "structured parser operation must own exactly one valid body region",
};

inline constexpr DiagnosticDefinition RepeatRequiresBound{
    .id = "PIR_REPEAT_REQUIRES_BOUND",
    .classification = DiagnosticClassification::Internal,
    .severity = DiagnosticSeverity::Error,
    .message = "parser.repeat_to_bound requires an active byte bound on its input state",
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
