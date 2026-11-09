// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <spicy/compiler/detail/pir/ir/diagnostic-definition.h>

namespace spicy::detail::pir::ir::diag {

// Field-use diagnostics. Keep IDs short and stable for warning suppression.

inline constexpr DiagnosticDefinition UnusedField{
    .id = "unused-field",
    .severity = DiagnosticSeverity::Warning,
    .message = "field '%s' is parsed but never used; consider making it 'skip'",
};

inline constexpr DiagnosticDefinition FieldReadBeforeParsed{
    .id = "field-read-before-parsed",
    .severity = DiagnosticSeverity::Error,
    .message = "field '%s' may be read before it is set",
};

inline constexpr DiagnosticDefinition FieldParsedHere{
    .id = "field-parsed-here",
    .severity = DiagnosticSeverity::Note,
    .message = "'%s' is parsed here",
};

} // namespace spicy::detail::pir::ir::diag
