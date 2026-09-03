// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <variant>
#include <vector>

#include <hilti/ast/forward.h>
#include <hilti/ast/location.h>
#include <hilti/base/logger.h>
#include <hilti/base/result.h>

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

/** PIR construction succeeded. Will carry the resulting PIR package. */
struct Success {};

/**
 * PIR cannot represent one or more constructs yet. This is the only outcome
 * that permits falling back to the standard code generator.
 */
struct Unsupported {
    std::vector<UnsupportedFeature> features;
};

/**
 * Outcome of a successful PIR build: either the resulting package, or the
 * constructs that kept PIR from representing the AST.
 */
using BuildOutcome = std::variant<Success, Unsupported>;

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
