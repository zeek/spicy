// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <spicy/compiler/detail/pir/ir/diagnostic-definition.h>

namespace spicy::detail::pir::ir::diag {

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

// --- Declaration membership, independent of any single TypeDecl's own fields walk --------------

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

} // namespace spicy::detail::pir::ir::diag
