// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <string_view>

namespace spicy::detail::pir::ir {

enum class DiagnosticSeverity { Error, Warning, Note };

/**
 * Internal is an internal compiler error (ie some compiler invariant).
 * User can reasonably occur within user code.
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
