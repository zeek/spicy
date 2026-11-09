// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <spicy/compiler/detail/pir/ir/diagnostic-definition.h>

namespace spicy::detail::pir::ir::diag {

// Field-use diagnostics. Keep IDs short and stable for warning suppression.

inline constexpr DiagnosticDefinition UnusedField{
    .id = "unused-field",
    .classification = DiagnosticClassification::User,
    .severity = DiagnosticSeverity::Warning,
    .message = "field '%s' is parsed but never used; consider making it 'skip'",
};

} // namespace spicy::detail::pir::ir::diag
