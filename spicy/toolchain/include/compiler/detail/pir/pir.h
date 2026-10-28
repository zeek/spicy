// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <variant>
#include <vector>

#include <hilti/ast/forward.h>
#include <hilti/ast/location.h>
#include <hilti/base/logger.h>
#include <hilti/base/result.h>

#include <spicy/compiler/detail/pir/ir/diagnostic.h>
#include <spicy/compiler/detail/pir/ir/package.h>

namespace spicy::logging::debug {
inline const hilti::logging::DebugStream PIR("spicy-pir");
} // namespace spicy::logging::debug

namespace spicy::detail::pir {

/** A construct that PIR cannot represent yet. */
struct UnsupportedFeature {
    std::string feature;      /**< the construct's name */
    std::string reason;       /**< why PIR cannot represent the construct */
    hilti::Location location; /**< where the construct appears in the source */
};

/** What a target adapter supplies for a foreign declaration that has no native symbol of its own. */
enum class TargetBindingKind {
    LinkedArtifactScope, /**< the `uint64` that identifies the linked artifact holding the compiled code */
};

/**
 * Associates a foreign declaration of the package with an implementation that the target adapter provides. The
 * declaration stays an ordinary foreign function to the package; only the target decides how to realize it.
 */
struct TargetBinding {
    ir::ForeignFunctionId function;
    TargetBindingKind kind;
};

/** PIR construction succeeded and owns a self-contained package with no AST references. */
struct Success {
    ir::Package package;
    std::vector<TargetBinding> bindings; /**< for the target adapter; not part of the package */
};

/**
 * PIR cannot represent one or more constructs yet. This is the only outcome
 * that permits falling back to the standard code generator.
 */
struct Unsupported {
    std::vector<UnsupportedFeature> features;
};

/**
 * PIR construction produced a malformed package. This is a hard failure: the
 * caller must render `diagnostics` and not proceed with code generation. The
 * package is retained only so diagnostics can render its package-relative
 * sites; it must not be treated as validated IR.
 */
struct Error {
    ir::Package package;
    std::vector<ir::Diagnostic> diagnostics;
};

/**
 * Used to determine the status of PIR build, for diagnostics or to see if
 * we should keep going with the build versus fallback.
 */
using BuildOutcome = std::variant<Success, Unsupported, Error>;

/**
 * Result of a PIR build. An error means PIR construction itself failed, which
 * is fatal; only an `Unsupported` outcome permits falling back to the standard
 * code generator.
 */
using BuildResult = hilti::Result<BuildOutcome>;

/**
 * Entry point for Spicy's experimental Parser IR (PIR).
 *
 * This runs on a fully resolved and validated Spicy AST, before the standard
 * code generator begins transforming that AST into HILTI. The phase is
 * read-only: it never modifies the AST, and the standard Spicy-to-HILTI path
 * remains authoritative for the code that's eventually produced.
 *
 * The builder only reports what it was able to represent; deciding what to do
 * with an `Unsupported` outcome is up to the caller.
 *
 * @param ctx AST context holding the AST to build PIR for
 * @return the build's outcome; currently always `Unsupported`
 */
BuildResult build(const hilti::ASTContext& ctx);

} // namespace spicy::detail::pir
