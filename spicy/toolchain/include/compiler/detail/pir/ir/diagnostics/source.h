// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <spicy/compiler/detail/pir/ir/diagnostic-definition.h>

namespace spicy::detail::pir::ir::diag {

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

} // namespace spicy::detail::pir::ir::diag
