// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <string_view>

namespace spicy::detail::pir::ir {

enum class DiagnosticSeverity { Error, Warning, Note };

/**
 * A user diagnostic's stable ID, severity, and message format.
 * Internal compiler errors use `InternalError` instead.
 */
struct DiagnosticDefinition {
    const char* id;
    DiagnosticSeverity severity;
    const char* message;
};

/** Definitions are identified by their stable ID; there is exactly one per catalog entry. */
constexpr bool operator==(const DiagnosticDefinition& a, const DiagnosticDefinition& b) {
    return std::string_view(a.id) == std::string_view(b.id);
}
constexpr bool operator!=(const DiagnosticDefinition& a, const DiagnosticDefinition& b) { return ! (a == b); }

} // namespace spicy::detail::pir::ir
