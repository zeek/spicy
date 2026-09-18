// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <string_view>

namespace spicy::detail::pir::ir {

enum class DiagnosticSeverity { Error, Warning, Note };

/**
 * Whether a diagnostic reports a violated PIR invariant (an internal compiler error, never
 * suppressible and not the user's fault) or a source-level condition a user could address.
 * Every diagnostic PIR's verifier currently produces is `Internal`: they all report malformed
 * PIR, which is a compiler bug, not something a well-formed Spicy program can trigger.
 */
enum class DiagnosticClassification { Internal, User };

/** A catalog entry fixing one diagnostic's stable ID, classification, severity, and message format. */
struct DiagnosticDefinition {
    const char* id;
    DiagnosticClassification classification;
    DiagnosticSeverity severity;
    const char* message;
};

/** Definitions are identified by their stable ID; there is exactly one per catalog entry. */
constexpr bool operator==(const DiagnosticDefinition& a, const DiagnosticDefinition& b) {
    return std::string_view(a.id) == std::string_view(b.id);
}
constexpr bool operator!=(const DiagnosticDefinition& a, const DiagnosticDefinition& b) { return ! (a == b); }

} // namespace spicy::detail::pir::ir
