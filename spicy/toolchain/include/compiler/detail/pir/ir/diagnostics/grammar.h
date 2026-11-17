// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <spicy/compiler/detail/pir/ir/diagnostic-definition.h>

namespace spicy::detail::pir::ir::diag {

// Look-ahead diagnostics. The parser decides with one token, so these reject grammars it cannot decide.

inline constexpr DiagnosticDefinition AmbiguousLoopEnd{
    .id = "ambiguous-loop-end",
    .severity = DiagnosticSeverity::Error,
    .message = "cannot tell where field '%s' ends: %s can start another element and also what follows",
};

inline constexpr DiagnosticDefinition AmbiguousSwitchCase{
    .id = "ambiguous-switch-case",
    .severity = DiagnosticSeverity::Error,
    .message = "cannot tell this case from an earlier one: %s can start both",
};

inline constexpr DiagnosticDefinition NoLookAhead{
    .id = "no-look-ahead",
    .severity = DiagnosticSeverity::Error,
    .message = "%s needs a look-ahead token, but no alternative starts with one",
};

inline constexpr DiagnosticDefinition NonTerminalLookAhead{
    .id = "non-terminal-look-ahead",
    .severity = DiagnosticSeverity::Error,
    .message = "%s cannot be decided with one token: '%s' is not a single token",
};

inline constexpr DiagnosticDefinition LookAheadTokenHere{
    .id = "look-ahead-token-here",
    .severity = DiagnosticSeverity::Note,
    .message = "%s can start %s here",
};

} // namespace spicy::detail::pir::ir::diag
